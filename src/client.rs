// SPDX-FileCopyrightText: 2026 Morgan Jones
//
// SPDX-License-Identifier: BlueOak-1.0.0

//! An in-process client for signing through a persisted remote signing key.
//!
//! This is the same path as `autopen sign`, exposed as a reusable function so
//! the PKCS#11 shim (a separate crate) can relay `C_Sign` to a running
//! `autopen serve` without duplicating the Cap'n Proto plumbing.

use camino::Utf8Path;
use color_eyre::eyre::{self, WrapErr as _};

use crate::{
    autopen_capnp::signer::sign_results, local::Bootstrap, signing_key::SigningKey,
    socket_activation::ReceivedSockets,
};

/// Signs `message` with the remote signing key persisted at `path`.
///
/// The key file is a `Remote` signing key (as produced by
/// `autopen signing-key remote create`): it carries the server socket path and
/// the file-reference handle, so this connects to the server, proves access to
/// the capability, and returns the detached signature. The signature is
/// verified against the key's verification key before being returned.
///
/// Runs its own current-thread Tokio runtime, so it may be called from a plain
/// synchronous (e.g. FFI) context.
///
/// # Errors
///
/// Returns an error if the runtime cannot be created, the key cannot be loaded,
/// or the signing request fails.
pub fn sign_with_remote_key(path: &str, message: &[u8]) -> eyre::Result<Vec<u8>> {
    let runtime = tokio::runtime::LocalRuntime::new().wrap_err("Failed to create Tokio runtime")?;
    runtime.block_on(async {
        let local = Bootstrap::new(ReceivedSockets::default());
        let signing_key: SigningKey = local.load(Utf8Path::new(path)).await?;
        let mut request = signing_key.into_signer().sign_request();
        request.get().set_message(message);
        let response = request
            .send()
            .promise
            .await
            .wrap_err("Failed to sign message")?;
        let signature = response
            .get()
            .and_then(sign_results::Reader::get_signature)
            .wrap_err("Failed to read signature")?;
        Ok(signature.to_vec())
    })
}
