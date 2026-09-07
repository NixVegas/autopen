// SPDX-FileCopyrightText: 2026 Morgan Jones
//
// SPDX-License-Identifier: BlueOak-1.0.0

//! Module state: the proxy objects (built from the signer's certificate) and
//! open sessions. Kept behind a mutex; all pointer marshalling happens in
//! `lib.rs`, so everything here operates on owned data.

use std::{env, fs, sync::Mutex};

use cryptoki_sys::{
    CK_ATTRIBUTE_TYPE, CK_CERTIFICATE_TYPE, CK_KEY_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE,
    CK_SESSION_HANDLE, CK_ULONG, CKC_X_509, CKK_RSA, CKO_CERTIFICATE, CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
};
use cryptoki_sys::{
    CKA_ALWAYS_SENSITIVE, CKA_DECRYPT, CKA_DERIVE, CKA_EXTRACTABLE, CKA_LOCAL,
    CKA_NEVER_EXTRACTABLE, CKA_SENSITIVE, CKA_UNWRAP,
};
use cryptoki_sys::{
    CKA_CERTIFICATE_TYPE, CKA_CLASS, CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS, CKA_PRIVATE,
    CKA_PUBLIC_EXPONENT, CKA_SIGN, CKA_SUBJECT, CKA_TOKEN, CKA_VALUE, CKA_VERIFY,
};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

/// Object handles (stable for the process lifetime).
pub(crate) const PRIVATE_KEY_HANDLE: CK_OBJECT_HANDLE = 1;
const H_PUBLIC_KEY: CK_OBJECT_HANDLE = 2;
const H_CERTIFICATE: CK_OBJECT_HANDLE = 3;

/// A single attribute value, in one of the three PKCS#11 shapes we emit.
#[derive(Clone)]
pub(crate) enum AttrVal {
    /// A `CK_ULONG` (encoded native-endian, as PKCS#11 templates expect).
    Ulong(CK_ULONG),
    /// A `CK_BBOOL`.
    Bool(bool),
    /// A raw byte string.
    Bytes(Vec<u8>),
}

impl AttrVal {
    /// The on-the-wire (C template) byte encoding of the value.
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ulong(v) => v.to_ne_bytes().to_vec(),
            Self::Bool(b) => vec![u8::from(*b)],
            Self::Bytes(b) => b.clone(),
        }
    }
}

/// A proxy object exposed by the module.
pub(crate) struct Object {
    /// The object's handle.
    pub(crate) handle: CK_OBJECT_HANDLE,
    /// Its attributes.
    attrs: Vec<(CK_ATTRIBUTE_TYPE, AttrVal)>,
}

impl Object {
    /// Returns the encoded value of attribute `type_`, if present.
    pub(crate) fn attr(&self, type_: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        self.attrs
            .iter()
            .find(|(t, _)| *t == type_)
            .map(|(_, v)| v.encode())
    }

    /// Whether the object matches a find template (every templated attribute
    /// present and byte-equal).
    fn matches(&self, template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)]) -> bool {
        template
            .iter()
            .all(|(t, want)| self.attr(*t).as_deref() == Some(want.as_slice()))
    }
}

/// An open session and its in-progress operations.
pub(crate) struct Session {
    /// The session handle.
    pub(crate) handle: CK_SESSION_HANDLE,
    /// Remaining handles for an active `C_FindObjects` (None if no find active).
    pub(crate) find: Option<Vec<CK_OBJECT_HANDLE>>,
    /// Buffered message for an active sign operation (None if no sign active).
    pub(crate) sign: Option<Vec<u8>>,
}

/// The whole module state.
pub(crate) struct State {
    /// Proxy objects (empty if `AUTOPEN_CERT` is unset/unreadable).
    objects: Vec<Object>,
    /// The RSA signature/modulus length in bytes, from the certificate (256 for
    /// RSA‐2048, 384 for RSA‐3072). Defaults to 384 when no cert is available.
    sig_len: usize,
    /// Open sessions.
    sessions: Vec<Session>,
    /// Next session handle to hand out.
    next_session: CK_SESSION_HANDLE,
}

impl State {
    /// Builds the state, reading the certificate from `AUTOPEN_CERT`.
    fn new() -> Self {
        let (objects, sig_len) = build_objects().unwrap_or_else(|err| {
            eprintln!("autopen-pkcs11: no objects available: {err}");
            (Vec::new(), 384)
        });
        Self {
            objects,
            sig_len,
            sessions: Vec::new(),
            next_session: 1,
        }
    }

    /// The RSA signature/modulus length in bytes for the proxy key.
    pub(crate) fn sig_len(&self) -> usize {
        self.sig_len
    }

    /// Opens a new session, returning its handle.
    pub(crate) fn open_session(&mut self) -> CK_SESSION_HANDLE {
        let handle = self.next_session;
        self.next_session += 1;
        self.sessions.push(Session {
            handle,
            find: None,
            sign: None,
        });
        handle
    }

    /// Begins a sign operation on `handle`'s session. Returns false if unknown.
    pub(crate) fn sign_init(&mut self, handle: CK_SESSION_HANDLE) -> bool {
        match self.session_mut(handle) {
            Some(session) => {
                session.sign = Some(Vec::new());
                true
            }
            None => false,
        }
    }

    /// Appends `data` to the active sign buffer. Returns false if no sign active.
    pub(crate) fn sign_update(&mut self, handle: CK_SESSION_HANDLE, data: &[u8]) -> bool {
        match self.session_mut(handle).and_then(|s| s.sign.as_mut()) {
            Some(buf) => {
                buf.extend_from_slice(data);
                true
            }
            None => false,
        }
    }

    /// Whether a sign operation is active on `handle`'s session.
    pub(crate) fn sign_active(&mut self, handle: CK_SESSION_HANDLE) -> bool {
        self.session_mut(handle).is_some_and(|s| s.sign.is_some())
    }

    /// Ends the active sign operation, returning its buffered message.
    pub(crate) fn sign_take(&mut self, handle: CK_SESSION_HANDLE) -> Option<Vec<u8>> {
        self.session_mut(handle).and_then(|s| s.sign.take())
    }

    /// Returns the session with the given handle, if open.
    pub(crate) fn session_mut(&mut self, handle: CK_SESSION_HANDLE) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|s| s.handle == handle)
    }

    /// Removes a session.
    pub(crate) fn close_session(&mut self, handle: CK_SESSION_HANDLE) -> bool {
        let before = self.sessions.len();
        self.sessions.retain(|s| s.handle != handle);
        self.sessions.len() != before
    }

    /// Begins a find on `handle`'s session, computing matching object handles.
    /// Returns false if the session is unknown.
    pub(crate) fn find_init(
        &mut self,
        handle: CK_SESSION_HANDLE,
        template: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
    ) -> bool {
        let matches: Vec<CK_OBJECT_HANDLE> = self
            .objects
            .iter()
            .filter(|o| o.matches(template))
            .map(|o| o.handle)
            .collect();
        match self.session_mut(handle) {
            Some(session) => {
                session.find = Some(matches);
                true
            }
            None => false,
        }
    }

    /// Returns up to `max` handles from the active find on `handle`.
    pub(crate) fn find_next(
        &mut self,
        handle: CK_SESSION_HANDLE,
        max: usize,
    ) -> Option<Vec<CK_OBJECT_HANDLE>> {
        let session = self.session_mut(handle)?;
        let remaining = session.find.as_mut()?;
        let n = max.min(remaining.len());
        Some(remaining.drain(..n).collect())
    }

    /// Ends the active find on `handle`.
    pub(crate) fn find_final(&mut self, handle: CK_SESSION_HANDLE) -> bool {
        match self.session_mut(handle) {
            Some(session) => {
                session.find = None;
                true
            }
            None => false,
        }
    }

    /// Returns the object with the given handle, if any.
    pub(crate) fn object(&self, handle: CK_OBJECT_HANDLE) -> Option<&Object> {
        self.objects.iter().find(|o| o.handle == handle)
    }
}

/// Global module state, initialized on first use.
static STATE: Mutex<Option<State>> = Mutex::new(None);

/// Runs `f` with the (lazily initialized) module state.
pub(crate) fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATE.lock().expect("module state mutex poisoned");
    f(guard.get_or_insert_with(State::new))
}

/// Builds the proxy objects (private key, public key, certificate) from the
/// certificate at `AUTOPEN_CERT`. The label defaults to `autopen` (override with
/// `AUTOPEN_LABEL`) and the id defaults to `[0x01]` (override with `AUTOPEN_ID`,
/// a hex string); the key and certificate share the id so consumers can pair
/// them.
fn build_objects() -> Result<(Vec<Object>, usize), String> {
    let path = env::var("AUTOPEN_CERT").map_err(|_| "AUTOPEN_CERT is not set".to_owned())?;
    let data = fs::read(&path).map_err(|err| format!("failed to read {path}: {err}"))?;

    let der: Vec<u8> = if data.starts_with(b"-----BEGIN") {
        let (_, pem) =
            parse_x509_pem(&data).map_err(|err| format!("failed to parse PEM cert: {err}"))?;
        pem.contents
    } else {
        data
    };

    let (_, cert) =
        X509Certificate::from_der(&der).map_err(|err| format!("failed to parse cert: {err}"))?;
    let (modulus, exponent) = match cert
        .public_key()
        .parsed()
        .map_err(|err| format!("failed to parse public key: {err}"))?
    {
        PublicKey::RSA(rsa) => (
            strip_leading_zeros(rsa.modulus),
            strip_leading_zeros(rsa.exponent),
        ),
        _ => return Err("certificate does not carry an RSA key".to_owned()),
    };
    let subject = cert.subject().as_raw().to_vec();
    // The signature length equals the modulus byte length (256 for RSA‐2048,
    // 384 for RSA‐3072); the shim advertises it to the PKCS#11 consumer.
    let sig_len = modulus.len();

    let label = env::var("AUTOPEN_LABEL").unwrap_or_else(|_| "autopen".to_owned());
    let id = match env::var("AUTOPEN_ID") {
        Ok(hex) => decode_hex(&hex).ok_or_else(|| format!("AUTOPEN_ID is not hex: {hex}"))?,
        Err(_) => vec![0x01],
    };

    let class = |c: CK_OBJECT_CLASS| AttrVal::Ulong(c);
    let common = |extra: Vec<(CK_ATTRIBUTE_TYPE, AttrVal)>| {
        let mut v = vec![
            (CKA_TOKEN, AttrVal::Bool(true)),
            (CKA_ID, AttrVal::Bytes(id.clone())),
            (CKA_LABEL, AttrVal::Bytes(label.clone().into_bytes())),
        ];
        v.extend(extra);
        v
    };

    let private_key = Object {
        handle: PRIVATE_KEY_HANDLE,
        attrs: common(vec![
            (CKA_CLASS, class(CKO_PRIVATE_KEY)),
            (CKA_KEY_TYPE, AttrVal::Ulong(CKK_RSA as CK_KEY_TYPE)),
            // Visible without login: the far-side daemon holds the real PIN.
            (CKA_PRIVATE, AttrVal::Bool(false)),
            (CKA_SIGN, AttrVal::Bool(true)),
            (CKA_MODULUS, AttrVal::Bytes(modulus.clone())),
            (CKA_PUBLIC_EXPONENT, AttrVal::Bytes(exponent.clone())),
            // Standard key-metadata booleans SunPKCS11 reads for a token key.
            (CKA_SENSITIVE, AttrVal::Bool(true)),
            (CKA_EXTRACTABLE, AttrVal::Bool(false)),
            (CKA_ALWAYS_SENSITIVE, AttrVal::Bool(true)),
            (CKA_NEVER_EXTRACTABLE, AttrVal::Bool(true)),
            (CKA_DECRYPT, AttrVal::Bool(false)),
            (CKA_UNWRAP, AttrVal::Bool(false)),
            (CKA_DERIVE, AttrVal::Bool(false)),
            (CKA_LOCAL, AttrVal::Bool(false)),
        ]),
    };
    let public_key = Object {
        handle: H_PUBLIC_KEY,
        attrs: common(vec![
            (CKA_CLASS, class(CKO_PUBLIC_KEY)),
            (CKA_KEY_TYPE, AttrVal::Ulong(CKK_RSA as CK_KEY_TYPE)),
            (CKA_VERIFY, AttrVal::Bool(true)),
            (CKA_MODULUS, AttrVal::Bytes(modulus)),
            (CKA_PUBLIC_EXPONENT, AttrVal::Bytes(exponent)),
        ]),
    };
    let certificate = Object {
        handle: H_CERTIFICATE,
        attrs: common(vec![
            (CKA_CLASS, class(CKO_CERTIFICATE)),
            (
                CKA_CERTIFICATE_TYPE,
                AttrVal::Ulong(CKC_X_509 as CK_CERTIFICATE_TYPE),
            ),
            (CKA_SUBJECT, AttrVal::Bytes(subject)),
            (CKA_VALUE, AttrVal::Bytes(der)),
        ]),
    };

    Ok((vec![private_key, public_key, certificate], sig_len))
}

/// Strips leading zero bytes from a big-endian integer (PKCS#11 wants the
/// unsigned magnitude, without the DER sign padding byte).
fn strip_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    bytes[start..].to_vec()
}

/// Decodes a lowercase/uppercase hex string into bytes.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_leading_zeros_removes_der_sign_byte() {
        assert_eq!(strip_leading_zeros(&[0x00, 0x80, 0x01]), vec![0x80, 0x01]);
        assert_eq!(
            strip_leading_zeros(&[0x01, 0x00, 0x01]),
            vec![0x01, 0x00, 0x01]
        );
        assert_eq!(strip_leading_zeros(&[0x00]), vec![0x00]);
    }

    #[test]
    fn decode_hex_parses_bytes() {
        assert_eq!(decode_hex("010d00"), Some(vec![0x01, 0x0d, 0x00]));
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(decode_hex("abc"), None);
    }

    #[test]
    fn ulong_encodes_native_endian() {
        assert_eq!(AttrVal::Ulong(3).encode(), 3usize.to_ne_bytes().to_vec());
        assert_eq!(AttrVal::Bool(true).encode(), vec![1]);
    }
}
