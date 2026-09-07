// SPDX-FileCopyrightText: 2026 Emily <hello@emily.moe>
//
// SPDX-License-Identifier: BlueOak-1.0.0

//! `rsa3072-pkcs1-sha256` verification keys.
//!
//! This is `RSASSA-PKCS1-v1_5` as defined in [Section 8.2 of RFC
//! 8017], using RSA keys with 3072‐bit moduli and SHA‐256 as the hash
//! function.
//!
//! Backed by the pure‐Rust `rsa` crate (num‐bigint), so it works on
//! CPUs without the BMI1/AVX features graviola requires.
//!
//! [Section 8.2 of RFC 8017]: <https://www.rfc-editor.org/info/rfc8017/#section-8.2>

use std::fmt::{self, Debug};

use rsa::{
    RsaPublicKey,
    pkcs1::{DecodeRsaPublicKey as _, EncodeRsaPublicKey as _},
    pkcs1v15,
    signature::Verifier as _,
    traits::PublicKeyParts as _,
};
use sha2::Sha256;

use crate::{
    autopen_capnp::verification_key::rsa3072_pkcs1_sha256,
    local::{Serialize, restorer},
    verification_key::{Verifier, VerifyError},
    x509,
};

/// The expected modulus length in bytes (3072 bits).
const MODULUS_LEN_BYTES: usize = 384;

/// An RSA verification key with a 3072‐bit modulus.
pub(crate) struct VerificationKey(RsaPublicKey);

impl VerificationKey {
    /// Decodes a verification key from the ASN.1 DER encoding of an
    /// `RSAPublicKey`, as defined in [Appendix A.1.1 of RFC 8017].
    ///
    /// [Appendix A.1.1 of RFC 8017]: <https://www.rfc-editor.org/info/rfc8017/#appendix-A.1.1>
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the modulus is not 3072‐bit.
    pub(crate) fn from_pkcs1_der(bytes: &[u8]) -> Result<Self, String> {
        let key = RsaPublicKey::from_pkcs1_der(bytes)
            .map_err(|err| format!("failed to decode RSAPublicKey: {err}"))?;
        Self::checked(key)
    }

    /// Enforces the expected modulus size.
    ///
    /// # Errors
    ///
    /// Returns an error if the modulus is not [`MODULUS_LEN_BYTES`] bytes.
    fn checked(key: RsaPublicKey) -> Result<Self, String> {
        if key.size() == MODULUS_LEN_BYTES {
            Ok(Self(key))
        } else {
            Err(format!(
                "expected a {MODULUS_LEN_BYTES}-byte modulus, got {}",
                key.size()
            ))
        }
    }

    /// Encodes the verification key into the ASN.1 DER encoding of an
    /// `RSAPublicKey`, as defined in [Appendix A.1.1 of RFC 8017].
    ///
    /// [Appendix A.1.1 of RFC 8017]: <https://www.rfc-editor.org/info/rfc8017/#appendix-A.1.1>
    #[expect(clippy::missing_panics_doc, reason = "invariant")]
    fn to_pkcs1_der(&self) -> Vec<u8> {
        self.0
            .to_pkcs1_der()
            .expect("a valid RSA public key should encode")
            .as_bytes()
            .to_vec()
    }
}

impl Verifier for VerificationKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        let key = pkcs1v15::VerifyingKey::<Sha256>::new(self.0.clone());
        let signature = pkcs1v15::Signature::try_from(signature).map_err(|_err| VerifyError)?;
        key.verify(message, &signature).map_err(|_err| VerifyError)
    }
}

impl x509::SubjectPublicKey for VerificationKey {
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }

    fn to_subject_public_key(&self) -> Vec<u8> {
        self.to_pkcs1_der()
    }
}

impl Debug for VerificationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("VerificationKey::from_pkcs1_der")
            .field(&self.to_pkcs1_der())
            .finish()
    }
}

impl Serialize for VerificationKey {
    type Owned = rsa3072_pkcs1_sha256::Owned;

    fn read_capnp(
        _restorer: &restorer::Client,
        reader: rsa3072_pkcs1_sha256::Reader<'_>,
    ) -> capnp::Result<Self> {
        Self::from_pkcs1_der(reader.get_pkcs1_der()?).map_err(capnp::Error::failed)
    }

    fn build_capnp(&self, mut builder: rsa3072_pkcs1_sha256::Builder<'_>) -> capnp::Result<()> {
        builder.set_pkcs1_der(&self.to_pkcs1_der());
        Ok(())
    }
}
