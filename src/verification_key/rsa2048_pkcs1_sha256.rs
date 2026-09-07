// SPDX-FileCopyrightText: 2026 Emily <hello@emily.moe>
//
// SPDX-License-Identifier: BlueOak-1.0.0

//! `rsa2048-pkcs1-sha256` verification keys.
//!
//! This is `RSASSA-PKCS1-v1_5` as defined in [Section 8.2 of RFC
//! 8017], using RSA keys with 2048‐bit moduli and SHA‐256 as the hash
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
    autopen_capnp::verification_key::rsa2048_pkcs1_sha256,
    local::{Serialize, restorer},
    verification_key::{Verifier, VerifyError},
    x509,
};

/// The expected modulus length in bytes (2048 bits).
const MODULUS_LEN_BYTES: usize = 256;

/// An RSA verification key with a 2048‐bit modulus.
pub(crate) struct VerificationKey(RsaPublicKey);

impl VerificationKey {
    /// Decodes a verification key from the ASN.1 DER encoding of an
    /// `RSAPublicKey`, as defined in [Appendix A.1.1 of RFC 8017].
    ///
    /// [Appendix A.1.1 of RFC 8017]: <https://www.rfc-editor.org/info/rfc8017/#appendix-A.1.1>
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails or the modulus is not 2048‐bit.
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
    type Owned = rsa2048_pkcs1_sha256::Owned;

    fn read_capnp(
        _restorer: &restorer::Client,
        reader: rsa2048_pkcs1_sha256::Reader<'_>,
    ) -> capnp::Result<Self> {
        Self::from_pkcs1_der(reader.get_pkcs1_der()?).map_err(capnp::Error::failed)
    }

    fn build_capnp(&self, mut builder: rsa2048_pkcs1_sha256::Builder<'_>) -> capnp::Result<()> {
        builder.set_pkcs1_der(&self.to_pkcs1_der());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_panics_doc,
        clippy::string_slice,
        clippy::arithmetic_side_effects,
        clippy::assertions_on_result_states,
        reason = "test code with trusted constant inputs; a panic signals failure"
    )]

    use super::*;

    /// Decodes a hex string into bytes.
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    // An RSA-2048 RSAPublicKey (RFC 8017 A.1.1) DER and a PKCS#1 v1.5 SHA-256
    // signature over MSG, generated with OpenSSL. This exercises the whole
    // RustCrypto path with no graviola op, so it passes on CPUs lacking the
    // BMI1/AVX features graviola requires (e.g. Tremont Atom).
    const PUB_DER: &str = "3082010a0282010100e39fd145036e9914a6a5d0534b341144d820fd938e80147cf7e2cd286ae816e387eec74dca6fc12b702ffdd1130b362003606e963a915541afd7639458531983525f3074d0f8c0a31aff0c87379e754f1f98e7ffb48a8a55776151d1cb143d9c0bc38ab6c5b7fdfa67938c9f88e66160bb7bd0c7b162f9e39ce55e6e78e430e62d6b1989b252f889789a1b517ea48b8446bd1bc11948b081db943d79742511fe8c7a1ce3f0d2221b9dfe67ad66a62f7c655eab47885fbae80d0d844e8ef6d6d90ff3aae7a5382299c617a65c9f95644d934cf571d002e22f0458d1a9ba21e6e556454ea9921e99001013f75decd37ec8ad3f57dcc139103044e45b49a1d414cb0203010001";
    const SIG: &str = "67e0c78fbc9516ceb1281c270a8929c461e93e966c58e57f76038748a71c0a1f5b9d95c09dc7727a04c6517ecf87e6cad5d31d1f026e29a718baac3e0fd92f55655509994511cbf895b1bdecc015d28162ff4dd4e2fb10fe120bf0738efa82c979ba10dc8d8e5361ec8e841e1ad5cd6fd75398cd3865a435b6889d248b4321c129e081c7fe501ee27a3ac44967054bb65f3aae9a6586ebdbf5a5ac766589f96fd9afb0c182ffdf936d1477e4649716448c98583da8d1ccb3c8fe992a9fbae2f7d50ad8889a3c9b3453b32490951307de4ecf4dbce5ab7966aee54a688acc629724ca00c1a43a3b64418ade243f63ed5de174a60f3a00c806ea229406ff74a480";
    const MSG: &[u8] = b"the quick brown fox";

    #[test]
    fn verifies_a_known_signature_without_graviola() {
        let vk = VerificationKey::from_pkcs1_der(&unhex(PUB_DER)).expect("valid 2048 pubkey");
        vk.verify(MSG, &unhex(SIG)).expect("signature should verify");
        // A tampered message must fail.
        assert!(vk.verify(b"the quick brown ox", &unhex(SIG)).is_err());
        // Re-encoding is canonical and matches the input DER.
        assert_eq!(vk.to_pkcs1_der(), unhex(PUB_DER));
    }

    #[test]
    fn rejects_a_malformed_key() {
        assert!(VerificationKey::from_pkcs1_der(b"\x30\x03\x02\x01\x00").is_err());
    }
}
