// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![no_std]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

/// Encryption and decryption implementation over a Poseidon cipher
#[cfg(feature = "cipher")]
pub mod cipher;

/// Module containing a fixed-length Poseidon hash implementation with one
/// input scalar and two output scalar
pub mod perm_uses;

/// Implementation for the Poseidon Sponge hash function
pub mod sponge;

/// Implementation of the Poseidon permutation based on the Hades strategy
pub mod hades;
