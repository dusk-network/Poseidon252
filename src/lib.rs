// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![no_std]
#![cfg_attr(feature = "alloc", warn(missing_docs), doc = include_str!("../README.md"))]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Encryption and decryption implementation over a Poseidon cipher
pub mod cipher;

/// Module containing a fixed-length Poseidon hash implementation
pub mod perm_uses;

/// Reference implementation for the Poseidon Sponge hash function
pub mod sponge;

/// The module handling poseidon-trees.
#[cfg(feature = "alloc")]
pub mod tree;
