// SPDX-FileCopyrightText: 2026 Morgan Jones
//
// SPDX-License-Identifier: BlueOak-1.0.0

//! Hardware (PKCS#11) signing keys.
//!
//! A [`HardwareSigner`] is built at runtime from an RFC 7512 `pkcs11:` URI (see
//! [`uri`]) and talks to a PKCS#11 token via `cryptoki`. It is never persisted
//! to Cap'n Proto: `autopen serve` constructs it from `--hardware-key` and binds
//! it to a file reference, and the build/client only ever sees a plain `Remote`
//! signing key.

pub(crate) mod uri;

use std::{
    cell::RefCell,
    collections::HashMap,
    fmt::{self, Debug},
    fs,
    rc::Rc,
};

use camino::{Utf8Path, Utf8PathBuf};
use color_eyre::eyre::{self, OptionExt as _, WrapErr as _};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error, RvError},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    types::AuthPin,
};
use tracing::{debug, error};

use crate::{
    autopen_capnp::signer,
    local::Serialize as _,
    signing_key::hardware::uri::{ResolvedKey, resolve_uri},
    verification_key::{self, VerificationKey},
};

/// A signing key backed by a PKCS#11 token, selected by a `pkcs11:` URI.
pub(crate) struct HardwareSigner {
    /// An open, logged‐in session on the token. Held for the process lifetime
    /// so we log in once (avoiding e.g. `YubiHSM` PIN‐retry lockout).
    session: Session,
    /// The private key object used for signing.
    private_key: ObjectHandle,
    /// The verification key, read from the token's public key at construction.
    verification_key: VerificationKey,
}

impl HardwareSigner {
    /// Builds a signer from a `pkcs11:` URI: opens the module, logs in, and
    /// reads the token's public key.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is invalid, the module/token/key cannot be
    /// opened, login fails, or the public key cannot be read.
    pub(crate) fn from_uri(uri: &str) -> eyre::Result<Self> {
        let (session, resolved) = open(uri)?;
        let verification_key = read_verification_key_from(&session, &resolved.key_id)?;
        let private_key = find_one(
            &session,
            &[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(resolved.key_id),
            ],
        )
        .wrap_err("Failed to find the private key on the token")?;
        Ok(Self {
            session,
            private_key,
            verification_key,
        })
    }

    /// Signs `message` with `rsa3072-pkcs1-sha256` on the token.
    ///
    /// The token hashes the message with SHA‐256 and produces an
    /// `RSASSA‐PKCS1‐v1_5` signature (`CKM_SHA256_RSA_PKCS`), matching autopen's
    /// message‐hashing `Signer` contract.
    ///
    /// # Errors
    ///
    /// Returns an error if the token operation fails.
    pub(crate) fn sign_raw(&self, message: &[u8]) -> eyre::Result<Vec<u8>> {
        self.session
            .sign(&Mechanism::Sha256RsaPkcs, self.private_key, message)
            .wrap_err("Token signing operation failed")
    }

    /// Converts the signer into a [`signer::Client`] for the Cap'n Proto
    /// `Signer` interface (as `serve` binds it to a file reference).
    pub(crate) fn into_signer(self) -> signer::Client {
        capnp_rpc::new_client(self)
    }
}

/// Reads the public key for `key_id` from a token session (used by the CLI's
/// `get-verification-key` without needing the private key).
///
/// # Errors
///
/// Returns an error if the URI is invalid or the public key cannot be read.
pub(crate) fn read_verification_key(uri: &str) -> eyre::Result<VerificationKey> {
    let (session, resolved) = open(uri)?;
    read_verification_key_from(&session, &resolved.key_id)
}

thread_local! {
    /// One initialized `Pkcs11` context per module path, shared across every key
    /// that uses that module. `C_Initialize` is global to a module, so loading +
    /// initializing the same module a second time returns
    /// `CKR_CRYPTOKI_ALREADY_INITIALIZED` (which is fatal to serving two keys
    /// from one token). Sharing one context — a cheap `Arc` clone — initializes
    /// each module exactly once and finalizes it once, when the process exits.
    static MODULES: RefCell<HashMap<Utf8PathBuf, Pkcs11>> = RefCell::new(HashMap::new());
}

/// Returns a shared, initialized `Pkcs11` context for `module_path`, loading and
/// initializing the module on first use and reusing it thereafter.
///
/// # Errors
///
/// Returns an error if the module cannot be loaded or initialized.
fn module_context(module_path: &Utf8Path) -> eyre::Result<Pkcs11> {
    MODULES.with_borrow_mut(|modules| {
        if let Some(pkcs11) = modules.get(module_path) {
            return Ok(pkcs11.clone());
        }
        let pkcs11 = Pkcs11::new(module_path)
            .wrap_err_with(|| format!("Failed to load PKCS#11 module {module_path}"))?;
        pkcs11
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .wrap_err("Failed to initialize the PKCS#11 module")?;
        modules.insert(module_path.to_owned(), pkcs11.clone());
        Ok(pkcs11)
    })
}

/// Opens and logs into a token session for the given URI.
///
/// # Errors
///
/// Returns an error if the URI is invalid, the module/token cannot be opened,
/// the pin-source file cannot be read, or login fails.
fn open(uri: &str) -> eyre::Result<(Session, ResolvedKey)> {
    let resolved = resolve_uri(uri)?;
    let pin = resolved
        .pin_source
        .as_ref()
        .map(|path| {
            fs::read_to_string(path)
                .map(|s| s.trim_end_matches(['\n', '\r']).to_owned())
                .wrap_err_with(|| format!("Failed to read pin-source file {path}"))
        })
        .transpose()?;

    let pkcs11 = module_context(&resolved.module_path)?;

    let slot = pkcs11
        .get_slots_with_token()
        .wrap_err("Failed to enumerate token slots")?
        .into_iter()
        .find(|&slot| {
            resolved.token.as_ref().is_none_or(|label| {
                pkcs11
                    .get_token_info(slot)
                    .is_ok_and(|info| info.label() == *label)
            })
        })
        .ok_or_eyre("No slot found for the requested token")?;

    let session = pkcs11
        .open_ro_session(slot)
        .wrap_err("Failed to open a token session")?;
    if let Some(pin) = pin {
        // PKCS#11 login state is per-token, not per-session: once another key on
        // the same token has logged this application in, `C_Login` returns
        // CKR_USER_ALREADY_LOGGED_IN — which is exactly the state we want, as all
        // sessions on the token share the login. Accept it as success.
        if let Err(err) = session.login(UserType::User, Some(&AuthPin::from(pin)))
            && !matches!(err, Error::Pkcs11(RvError::UserAlreadyLoggedIn, _))
        {
            return Err(err).wrap_err("Failed to log into the token");
        }
    }
    Ok((session, resolved))
}

/// Reads the RSA public key (`CKA_MODULUS`/`CKA_PUBLIC_EXPONENT`) for `key_id`
/// from the token and builds a [`VerificationKey`].
///
/// # Errors
///
/// Returns an error if the public key cannot be found or read, or if it is not
/// a valid RSA key.
fn read_verification_key_from(session: &Session, key_id: &[u8]) -> eyre::Result<VerificationKey> {
    let public_key = find_one(
        session,
        &[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Id(key_id.to_vec()),
        ],
    )
    .wrap_err("Failed to find the public key on the token")?;

    let mut modulus = None;
    let mut exponent = None;
    for attr in session
        .get_attributes(
            public_key,
            &[AttributeType::Modulus, AttributeType::PublicExponent],
        )
        .wrap_err("Failed to read public key attributes")?
    {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "cryptoki's Attribute enum is large and non-exhaustive"
        )]
        match attr {
            Attribute::Modulus(value) => modulus = Some(value),
            Attribute::PublicExponent(value) => exponent = Some(value),
            _ => {}
        }
    }
    let modulus = modulus.ok_or_eyre("Token public key has no modulus")?;
    let exponent = exponent.ok_or_eyre("Token public key has no public exponent")?;

    let der = rsa_public_key_der(&modulus, &exponent);
    // Select the algorithm by the token key's modulus size (raw CKA_MODULUS is
    // 256 bytes for RSA‐2048, 384 for RSA‐3072). The verification key is the
    // portable RustCrypto one, so no graviola op runs on the daemon host.
    Ok(match modulus.len() {
        256 => verification_key::rsa2048_pkcs1_sha256::VerificationKey::from_pkcs1_der(&der)
            .map_err(|err| eyre::eyre!("Token public key: {err}"))?
            .into(),
        384 => verification_key::rsa3072_pkcs1_sha256::VerificationKey::from_pkcs1_der(&der)
            .map_err(|err| eyre::eyre!("Token public key: {err}"))?
            .into(),
        len => eyre::bail!("Unsupported RSA modulus size: {len} bytes (want 256 or 384)"),
    })
}

/// Finds exactly one object matching `template`.
///
/// # Errors
///
/// Returns an error if the search fails or does not match exactly one object.
fn find_one(session: &Session, template: &[Attribute]) -> eyre::Result<ObjectHandle> {
    let mut objects = session
        .find_objects(template)
        .wrap_err("Failed to search for token objects")?
        .into_iter();
    let object = objects
        .next()
        .ok_or_eyre("No matching object on the token")?;
    if objects.next().is_some() {
        eyre::bail!("Multiple matching objects on the token; refine the id/token");
    }
    Ok(object)
}

/// Encodes an `RSAPublicKey` DER structure (RFC 8017 Appendix A.1.1) from raw
/// big‐endian modulus and exponent bytes: `SEQUENCE { INTEGER, INTEGER }`.
fn rsa_public_key_der(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut body = der_uint(modulus);
    body.extend(der_uint(exponent));
    der_tlv(0x30, &body)
}

/// Encodes a DER `INTEGER` from big‐endian bytes (minimal, non‐negative).
fn der_uint(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zero bytes, keeping at least one byte.
    let mut value = bytes;
    while let [0, rest @ ..] = value {
        if rest.is_empty() {
            break;
        }
        value = rest;
    }
    let mut content = Vec::new();
    // Prepend 0x00 if the high bit is set, so the INTEGER stays non‐negative.
    if value.first().is_none_or(|&b| b & 0x80 != 0) {
        content.push(0x00);
    }
    content.extend_from_slice(value);
    der_tlv(0x02, &content)
}

/// Wraps `content` in a DER TLV with the given tag and definite length.
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    match u8::try_from(len) {
        // Short form: a single length byte below 0x80.
        Ok(short) if short < 0x80 => out.push(short),
        // Long form: 0x80 | number-of-length-bytes, then the big‐endian length.
        _ => {
            let len_bytes = len.to_be_bytes();
            let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(0);
            let significant = len_bytes.get(start..).unwrap_or_default();
            let count = u8::try_from(significant.len()).unwrap_or(0);
            out.push(0x80 | count);
            out.extend_from_slice(significant);
        }
    }
    out.extend_from_slice(content);
    out
}

impl signer::Server for HardwareSigner {
    async fn sign(
        self: Rc<Self>,
        params: signer::SignParams,
        mut results: signer::SignResults,
    ) -> capnp::Result<()> {
        let message = params.get()?.get_message()?;
        let signature = self.sign_raw(message).map_err(|err| {
            error!(error = ?err);
            capnp::Error::failed("Failed to sign message".to_owned())
        })?;
        if signature.len() != self.verification_key.signature_len() {
            error!(len = signature.len(), "unexpected signature length");
            return Err(capnp::Error::failed(
                "Unexpected signature length".to_owned(),
            ));
        }
        let signature_len = u32::try_from(signature.len())
            .map_err(|_err| capnp::Error::failed("Signature too long".to_owned()))?;
        results
            .get()
            .init_signature(signature_len)
            .copy_from_slice(&signature);
        Ok(())
    }

    async fn get_verification_key(
        self: Rc<Self>,
        _params: signer::GetVerificationKeyParams,
        mut results: signer::GetVerificationKeyResults,
    ) -> capnp::Result<()> {
        let mut results = results.get();
        self.verification_key
            .build_capnp(results.reborrow().init_verification_key())?;
        debug!(results = ?results.into_reader());
        Ok(())
    }
}

impl Debug for HardwareSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HardwareSigner")
            .field("verification_key", &self.verification_key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        reason = "tests signal failure by returning an error"
    )]

    use color_eyre::eyre::ensure;

    use super::*;

    // Gated: only runs when a token is configured via AUTOPEN_TEST_PKCS11_URI
    // (e.g. a kryoptic token). Signs a message on the token and verifies the
    // signature with the verification key read from the token.
    #[test]
    fn signs_and_self_verifies_on_token() -> eyre::Result<()> {
        use crate::verification_key::Verifier as _;
        let Ok(uri) = std::env::var("AUTOPEN_TEST_PKCS11_URI") else {
            eprintln!("skipping: AUTOPEN_TEST_PKCS11_URI not set");
            return Ok(());
        };
        let signer = HardwareSigner::from_uri(&uri)?;
        let message = b"the quick brown fox";
        let signature = signer.sign_raw(message)?;
        ensure!(
            signature.len() == signer.verification_key.signature_len(),
            "unexpected signature length: {}",
            signature.len()
        );
        read_verification_key(&uri)?.verify(message, &signature)?;
        Ok(())
    }

    #[test]
    fn rsa_public_key_der_wraps_two_integers() -> eyre::Result<()> {
        // exponent 65537 = 0x010001; small modulus with high bit set gets a
        // leading 0x00 so the INTEGER stays non-negative.
        let der = rsa_public_key_der(&[0x80, 0x01], &[0x01, 0x00, 0x01]);
        ensure!(
            der == vec![
                0x30, 0x0a, // SEQUENCE, len 10
                0x02, 0x03, 0x00, 0x80, 0x01, // INTEGER 0x008001
                0x02, 0x03, 0x01, 0x00, 0x01, // INTEGER 0x010001
            ],
            "unexpected DER encoding: {der:02x?}"
        );
        Ok(())
    }
}
