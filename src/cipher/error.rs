// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
use thiserror::Error;

/// Error definitions for the decription process
#[derive(Error, Debug)]
pub enum CipherError {
    /// Error spawned when there is an inconsistency on the decryption
    #[error("Decription failed for the provided secret+nonce")]
    FailedDecrypt,
}
