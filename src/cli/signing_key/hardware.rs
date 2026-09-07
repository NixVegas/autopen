// SPDX-FileCopyrightText: 2026 Morgan Jones
//
// SPDX-License-Identifier: BlueOak-1.0.0

//! The `autopen signing-key hardware` subcommand.

use camino::Utf8PathBuf;
use color_eyre::eyre;

use crate::{
    cli::Subcommand,
    local::{self, Bootstrap, Secrecy},
    signing_key::hardware,
};

/// Commands for PKCS#11 token (hardware) signing keys.
#[cfg_attr(
    // Work around <https://github.com/rust-lang/rust-clippy/issues/16934>.
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "subcommands are documented by their respective types"
    )
)]
#[derive(Debug, clap::Subcommand)]
pub(crate) enum Command {
    GetVerificationKey(GetVerificationKey),
}

impl Subcommand for Command {
    async fn run(self, local: Bootstrap) -> eyre::Result<()> {
        match self {
            Self::GetVerificationKey(cmd) => cmd.run(local).await,
        }
    }
}

/// Write the verification key for a PKCS#11 token key selected by a `pkcs11:` URI.
///
/// Reads the token's public key; the private key never leaves the token.
#[derive(Debug, clap::Args)]
pub(crate) struct GetVerificationKey {
    /// The RFC 7512 `pkcs11:` URI selecting the token key.
    #[arg(long, value_name = "URI")]
    pkcs11_uri: String,
    /// The file to write the verification key to.
    #[arg(long, value_name = "PATH")]
    output: Utf8PathBuf,
}

impl Subcommand for GetVerificationKey {
    #[tracing::instrument(level = tracing::Level::DEBUG, skip(_local))]
    async fn run(self, _local: Bootstrap) -> eyre::Result<()> {
        let verification_key = hardware::read_verification_key(&self.pkcs11_uri)?;
        local::save(&self.output, &verification_key, Secrecy::Public).await?;
        Ok(())
    }
}
