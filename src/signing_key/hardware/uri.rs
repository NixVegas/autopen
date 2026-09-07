// SPDX-FileCopyrightText: 2026 Morgan Jones
//
// SPDX-License-Identifier: BlueOak-1.0.0

//! Minimal RFC 7512 `pkcs11:` URI parsing.
//!
//! We parse only the attributes autopen's hardware signer needs, and
//! deliberately hand‐roll it rather than pull in a crate: the available
//! `pkcs11-uri` crate drags in the unmaintained legacy `pkcs11` crate and an
//! old `libloading`, a needless second PKCS#11 binding and audit risk.
//!
//! See [RFC 7512](https://www.rfc-editor.org/info/rfc7512).

use camino::Utf8PathBuf;
use color_eyre::eyre::{self, OptionExt as _, bail, eyre};

/// A PKCS#11 key selected by a `pkcs11:` URI.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResolvedKey {
    /// The path to the PKCS#11 module (`module-path`).
    pub module_path: Utf8PathBuf,
    /// The token label (`token`), if given.
    pub token: Option<String>,
    /// The object id (`id`), decoded to raw `CKA_ID` bytes.
    pub key_id: Vec<u8>,
    /// The object label (`object`), if given.
    pub object: Option<String>,
    /// The path the PIN is read from (`pin-source=file:<path>`), if given.
    pub pin_source: Option<Utf8PathBuf>,
}

/// Parses a `pkcs11:` URI into a [`ResolvedKey`].
///
/// Only `module-path`, `token`, `id`, `object`, and `pin-source` are
/// interpreted; other attributes are ignored.
///
/// # Errors
///
/// Returns an error if the URI is not a `pkcs11:` URI, if `module-path` or
/// `id` is missing, if `pin-value` is present (a secret must never be embedded
/// in a URI), or if `pin-source` is not a `file:` URI.
pub(crate) fn resolve_uri(uri: &str) -> eyre::Result<ResolvedKey> {
    let body = uri
        .strip_prefix("pkcs11:")
        .ok_or_eyre("not a pkcs11: URI")?;

    // Path attributes are `;`‐separated; an optional `?` introduces
    // `&`‐separated query attributes (RFC 7512 §2.3).
    let (path, query) = match body.split_once('?') {
        Some((path, query)) => (path, query),
        None => (body, ""),
    };
    let attrs = path
        .split(';')
        .flat_map(|s| s.split(','))
        .chain(query.split('&'))
        .filter(|s| !s.is_empty());

    let mut module_path = None;
    let mut token = None;
    let mut key_id = None;
    let mut object = None;
    let mut pin_source = None;

    for attr in attrs {
        let (name, value) = attr
            .split_once('=')
            .ok_or_else(|| eyre!("malformed pkcs11 URI attribute {attr:?}"))?;
        match name {
            "id" => key_id = Some(pct_decode(value)?),
            "token" => token = Some(pct_decode_str(value)?),
            "object" => object = Some(pct_decode_str(value)?),
            "module-path" => module_path = Some(Utf8PathBuf::from(pct_decode_str(value)?)),
            "pin-value" => bail!("pin-value is not allowed in a pkcs11 URI; use pin-source"),
            "pin-source" => {
                let source = pct_decode_str(value)?;
                let file = source
                    .strip_prefix("file:")
                    .ok_or_else(|| eyre!("pin-source must be a file: URI, got {source:?}"))?;
                pin_source = Some(Utf8PathBuf::from(file));
            }
            _ => {}
        }
    }

    Ok(ResolvedKey {
        module_path: module_path.ok_or_eyre("pkcs11 URI is missing module-path")?,
        token,
        key_id: key_id.ok_or_eyre("pkcs11 URI is missing id")?,
        object,
        pin_source,
    })
}

/// Percent‐decodes a URI component into raw bytes.
///
/// # Errors
///
/// Returns an error if a percent‐escape is truncated or not valid hexadecimal.
fn pct_decode(s: &str) -> eyre::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes
                .next()
                .ok_or_else(|| eyre!("truncated percent-escape in {s:?}"))?;
            let lo = bytes
                .next()
                .ok_or_else(|| eyre!("truncated percent-escape in {s:?}"))?;
            let hex = [hi, lo];
            let hex = std::str::from_utf8(&hex).map_err(|_err| eyre!("invalid percent-escape"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_err| eyre!("invalid percent-escape"))?);
        } else {
            out.push(b);
        }
    }
    Ok(out)
}

/// Percent‐decodes a URI component into a UTF‐8 string.
///
/// # Errors
///
/// Returns an error if the escape is malformed or the result is not UTF‐8.
fn pct_decode_str(s: &str) -> eyre::Result<String> {
    String::from_utf8(pct_decode(s)?).map_err(|_err| eyre!("invalid UTF-8 in pkcs11 URI value"))
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        reason = "tests signal failure by returning an error"
    )]

    use color_eyre::eyre::{bail, ensure};

    use super::*;

    #[test]
    fn parses_a_full_uri() -> eyre::Result<()> {
        let uri = "pkcs11:token=YubiHSM;id=%01%0d%00;type=private;object=test\
                   ?module-path=/nix/store/x/yubihsm_pkcs11.so&pin-source=file:/etc/nixpkcs/user.pin";
        let resolved = resolve_uri(uri)?;
        ensure!(
            resolved
                == ResolvedKey {
                    module_path: "/nix/store/x/yubihsm_pkcs11.so".into(),
                    token: Some("YubiHSM".to_owned()),
                    key_id: vec![0x01, 0x0d, 0x00],
                    object: Some("test".to_owned()),
                    pin_source: Some("/etc/nixpkcs/user.pin".into()),
                },
            "unexpected parse result: {resolved:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_pin_value() -> eyre::Result<()> {
        let uri = "pkcs11:id=%01?module-path=/x.so&pin-value=1234";
        let Err(err) = resolve_uri(uri) else {
            bail!("pin-value must be rejected");
        };
        ensure!(
            err.to_string().contains("pin-value"),
            "error should mention pin-value: {err}"
        );
        Ok(())
    }

    #[test]
    fn rejects_non_file_pin_source() -> eyre::Result<()> {
        let uri = "pkcs11:id=%01?module-path=/x.so&pin-source=exec:/bin/echo";
        ensure!(
            resolve_uri(uri).is_err(),
            "a non-file pin-source must be rejected"
        );
        Ok(())
    }

    #[test]
    fn requires_module_path_and_id() -> eyre::Result<()> {
        ensure!(
            resolve_uri("pkcs11:id=%01").is_err(),
            "a missing module-path must be rejected"
        );
        ensure!(
            resolve_uri("pkcs11:?module-path=/x.so").is_err(),
            "a missing id must be rejected"
        );
        Ok(())
    }

    #[test]
    fn rejects_non_pkcs11_scheme() -> eyre::Result<()> {
        ensure!(
            resolve_uri("https://example.com").is_err(),
            "a non-pkcs11 scheme must be rejected"
        );
        Ok(())
    }
}
