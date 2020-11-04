// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

pub use cipher::PoseidonCipher;
pub use error::CipherError;

/// Maximum number of scalars allowed per message
pub const MESSAGE_CAPACITY: usize = 2;

/// Number of scalars used in a cipher
pub const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;

/// Number of bytes used by from/to bytes `PoseidonCipher` function
pub const CIPHER_BYTES_SIZE: usize = CIPHER_SIZE * 32;

/// Bytes consumed on serialization of the poseidon cipher
///
/// This is kept for backwards compatibility since the constant definition is
/// redundant to [`CIPHER_BYTES_SIZE`]
pub const ENCRYPTED_DATA_SIZE: usize = CIPHER_SIZE * 32;

/// [`PoseidonCipher`] definition
pub mod cipher;

/// Error definition for the cipher generation process
pub mod error;

#[cfg(test)]
mod tests;

/// Plonk gadget for Poseidon encryption
pub mod zk;
