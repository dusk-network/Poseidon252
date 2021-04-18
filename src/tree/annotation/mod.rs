// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::tree::PoseidonLeaf;
use canonical::{Canon, Store};
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Annotation, Cardinality, Child, Compound, Step, Walk};
use nstack::NStack;

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

/// This trait will grant the ability of tree traversal using the `Branch::walk`
/// for a provided annotation
pub trait PoseidonWalkableAnnotation<C, D, L, A>:
    PoseidonTreeAnnotation<L>
where
    C: Compound<A>,
    A: Annotation<L>,
    C: Clone,
    D: Clone,
    L: PoseidonLeaf,
{
    /// Traversal logic of the walkable annotation
    ///
    /// This will define the traversal path over the tree provided the generic data.
    ///
    /// The purpose of the data is to act as a filter over annotations, and this will be equally
    /// passed to leaves and nodes.
    fn poseidon_walk(walk: Walk<C, A>, data: D) -> Step;

    /// Uses the internal implementation of `poseidon_walk` to check if a leaf is compatible with
    /// a provided data.
    fn poseidon_leaf_found(leaf: &L, data: D) -> bool {
        match Self::poseidon_walk(Child::Leaf(leaf), data) {
            Step::Found(_) => true,
            _ => false,
        }
    }
}
