// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonLeaf;
use canonical::{Canon, Store};
use core::borrow::Borrow;
use dusk_plonk::prelude::*;
use microkelvin::{Annotation, Cardinality, Compound, Step, Walk};
use nstack::NStack;

mod max;
mod poseidon;

pub use max::PoseidonMaxAnnotation;
pub use poseidon::PoseidonAnnotation;

/// Any structure that implements this trait is guaranteed to be compatible
/// as a poseidon tree annotation
pub trait PoseidonTreeAnnotation<L, S>:
    Canon<S>
    + Annotation<NStack<L, Self, S>, S>
    + Borrow<Cardinality>
    + Borrow<BlsScalar>
where
    L: PoseidonLeaf<S>,
    S: Store,
{
}

/// This trait will grant the ability of tree traversal using the `Branch::walk`
/// for a provided annotation
pub trait PoseidonWalkableAnnotation<C, D, L, S>:
    PoseidonTreeAnnotation<L, S>
where
    C: Compound<S>,
    C: Clone,
    D: Clone,
    L: PoseidonLeaf<S>,
    S: Store,
{
    fn poseidon_walk(walk: Walk<'_, C, S>, data: D) -> Step<'_, C, S>;
}
