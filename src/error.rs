// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::fmt;
#[cfg(feature = "std")]
use std::fmt::{Display, Result};

/// Poseidon error variants
#[derive(Clone, Debug)]
pub enum Error {
    /// Error pushing to the poseidon tree
    TreePushFailed,
    /// Error on pop of the tree
    TreePopFailed,
    /// Error fetching the Nth item from the tree
    TreeGetFailed,
    /// Failed to obtain a Branch from a tree.
    TreeBranchFailed,
    /// Failed to obtain an Iterator from a tree.
    TreeIterFailed,
    /// Decryption failed for the provided secret+nonce
    CipherDecryptionFailed,
}

#[cfg(feature = "std")]
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result {
        write!(f, "Dusk-Poseidon Error: {:?}", &self)
    }
}
