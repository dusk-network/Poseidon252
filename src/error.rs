// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_safe::Error as SafeError;

/// Defines all possible error variants for SAFE
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// A call to during the lifetime of the [`safe::Sponge`] that doesn't fit
    /// the io-pattern.
    IOPatternViolation,

    /// An invalid io-pattern.
    InvalidIOPattern,

    /// The input doesn't yield enough input elements.
    TooFewInputElements,
}

impl From<SafeError> for Error {
    fn from(safe_error: SafeError) -> Self {
        match safe_error {
            SafeError::IOPatternViolation => Self::IOPatternViolation,
            SafeError::InvalidIOPattern => Self::InvalidIOPattern,
            SafeError::TooFewInputElements => Self::TooFewInputElements,
        }
    }
}
