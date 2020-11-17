// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::fmt;

#[cfg(feature = "std")]
use std::{error as std_error, fmt as std_fmt};

/// Poseidon error variants
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error<E: fmt::Debug> {
    /// Error pushing to the poseidon tree
    TreePushFailed(E),
    /// Error on pop of the tree
    TreePopFailed(E),
    /// Error fetching the Nth item from the tree
    TreeGetFailed(E),
    /// Decryption failed for the provided secret+nonce
    CipherDecryptionFailed,
}

#[cfg(feature = "std")]
impl<E: fmt::Debug> std_fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std_fmt::Result {
        write!(f, "Poseidon252 Error: {:?}", &self)
    }
}

#[cfg(feature = "std")]
impl<E: 'static + fmt::Debug + std_error::Error> std_error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn std_error::Error + 'static)> {
        match &self {
            Self::TreePushFailed(e) => Some(e),
            Self::TreePopFailed(e) => Some(e),
            Self::TreeGetFailed(e) => Some(e),
            _ => None,
        }
    }
}
