// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module defines a Wrap-up over the dusk-bls12_381 to define it's kelvin
//! storage traits

use canonical::Canon;
use canonical_derive::Canon;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use std::borrow::Borrow;

/// This struct is a Wrapper type over the bls12-381 `Scalar` which has implemented
/// inside the logic to allows `Kelvin` Merkle Trees understand how to store `Scalar`s
/// inside of their leaves.
///
/// This Struct is the one that we will use inside of our SmartContract storage logic to
/// encode/compress all of our Data Structures data into a single `Scalar`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Canon)]
pub struct StorageScalar(pub BlsScalar);

impl Default for StorageScalar {
    fn default() -> Self {
        StorageScalar(BlsScalar::default())
    }
}

impl Borrow<BlsScalar> for StorageScalar {
    fn borrow(&self) -> &BlsScalar {
        &self.0
    }
}

impl From<&StorageScalar> for StorageScalar {
    fn from(s: &StorageScalar) -> Self {
        s.clone()
    }
}

impl From<u64> for StorageScalar {
    fn from(val: u64) -> StorageScalar {
        StorageScalar(BlsScalar::from(val))
    }
}

impl From<BlsScalar> for StorageScalar {
    fn from(s: BlsScalar) -> Self {
        Self(s)
    }
}

// This is implemented since `PoseidonAnnotation` wraps up over `StorageScalar`.
// Therefore, in rust to get the interal `Scalar` from the annotation you'll
// need to call `annotation.0.0` and this is not valid.
// This trait impl solves the problem.
impl Into<BlsScalar> for StorageScalar {
    fn into(self) -> BlsScalar {
        self.0
    }
}
