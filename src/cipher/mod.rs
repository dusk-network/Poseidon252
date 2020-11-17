// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod cipher;

#[cfg(test)]
mod tests;

#[cfg(feature = "std")]
mod zk;

pub use cipher::PoseidonCipher;

#[cfg(feature = "std")]
pub use zk::{poseidon_cipher_decrypt, poseidon_cipher_encrypt};
