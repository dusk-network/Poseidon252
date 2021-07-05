// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::tree::PoseidonLeaf;
use canonical::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Annotation, Cardinality};

mod max;
mod poseidon;

pub use max::PoseidonMaxAnnotation;
pub use poseidon::PoseidonAnnotation;

/// Any structure that implements this trait is guaranteed to be compatible
/// as a poseidon tree annotation
pub trait PoseidonTreeAnnotation<L>:
    Default + Canon + Annotation<L> + Borrow<Cardinality> + Borrow<BlsScalar>
where
    L: PoseidonLeaf,
{
}
