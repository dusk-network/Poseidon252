// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![no_std]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

extern crate alloc;

mod error;
pub use error::Error;

mod hades;
pub use hades::WIDTH as HADES_WIDTH;

mod hash;
#[cfg(feature = "zk")]
pub use hash::gadget::HashGadget;
pub use hash::{Domain, Hash};

#[cfg(feature = "cipher")]
mod cipher;
#[cfg(feature = "cipher")]
pub use cipher::PoseidonCipher;
#[cfg(feature = "cipher")]
#[cfg(feature = "zk")]
pub use cipher::{
    zk::decrypt as decrypt_gadget, zk::encrypt as encrypt_gadget,
};
