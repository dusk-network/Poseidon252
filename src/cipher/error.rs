use thiserror::Error;

/// Error definitions for the decription process
#[derive(Error, Debug)]
pub enum CipherError {
    /// Error spawned when there is an inconsistency on the decryption
    #[error("Decription failed for the provided secret+nonce")]
    FailedDecrypt,
}
