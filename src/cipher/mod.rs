// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
pub use cipher::PoseidonCipher;
pub use error::CipherError;

/// Maximum number of scalars allowed per message
pub const MESSAGE_CAPACITY: usize = 2;

/// Number of scalars used in a cipher
pub const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;

/// Number of bytes used by from/to bytes `PoseidonCipher` function
pub const CIPHER_BYTES_SIZE: usize = CIPHER_SIZE * 32;

/// Bytes consumed on serialization of the poseidon cipher
pub const ENCRYPTED_DATA_SIZE: usize = CIPHER_SIZE * 32;

/// [`PoseidonCipher`] definition
pub mod cipher;

/// Error definition for the cipher generation process
pub mod error;

#[cfg(test)]
mod tests;

/// Plonk gadget for Poseidon encryption
pub mod zk;
