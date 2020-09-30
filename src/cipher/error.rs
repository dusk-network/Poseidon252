// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use thiserror::Error;

/// Error definitions for the decription process
#[derive(Error, Debug)]
pub enum CipherError {
    /// Error spawned when there is an inconsistency on the decryption
    #[error("Decription failed for the provided secret+nonce")]
    FailedDecrypt,
}
