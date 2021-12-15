// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod hash;

#[cfg(feature = "alloc")]
mod gadget;

#[cfg(feature = "alloc")]
mod truncated;

pub use hash::hash;

#[cfg(feature = "alloc")]
pub use gadget::gadget;

#[cfg(feature = "alloc")]
pub use truncated::{gadget as truncated_gadget, hash as truncated_hash};
