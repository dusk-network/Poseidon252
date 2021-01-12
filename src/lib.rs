// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(external_doc)]
#![doc(include = "../README.md")]
#![warn(missing_docs)]

/// Encryption and decryption implementation over a Poseidon cipher
pub mod cipher;
/// Module containing a fixed-length Poseidon hash implementation
pub mod perm_uses;
/// Reference implementation for the Poseidon Sponge hash function
pub mod sponge;
/// The module handling posedion-trees.
#[cfg(feature = "canon")]
pub mod tree;

mod error;

pub use error::Error;
