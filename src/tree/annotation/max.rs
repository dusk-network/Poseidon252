// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{PoseidonAnnotation, PoseidonTreeAnnotation};
use crate::tree::PoseidonLeaf;
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Annotation, Cardinality, Combine, Compound, Keyed, MaxKey};

/// Extends the standard [`PoseidonAnnotation`] with an annotation that holds an agnostic maximum
/// value
///
/// This maximum value is representes as `u64`, and the tree is iterable over it
#[derive(Debug, Clone, Canon, Default)]
pub struct PoseidonMaxAnnotation {
    poseidon: PoseidonAnnotation,
    max: MaxKey<u64>,
}

impl Borrow<Cardinality> for PoseidonMaxAnnotation {
    fn borrow(&self) -> &Cardinality {
        self.poseidon.borrow()
    }
}

impl Borrow<BlsScalar> for PoseidonMaxAnnotation {
    fn borrow(&self) -> &BlsScalar {
        self.poseidon.borrow()
    }
}

impl Borrow<MaxKey<u64>> for PoseidonMaxAnnotation {
    fn borrow(&self) -> &MaxKey<u64> {
        &self.max
    }
}

impl<L> Annotation<L> for PoseidonMaxAnnotation
where
    L: PoseidonLeaf,
    L: Borrow<u64>,
    L: Keyed<u64>,
{
    fn from_leaf(leaf: &L) -> Self {
        let poseidon = PoseidonAnnotation::from_leaf(leaf);
        let max = <MaxKey<u64> as Annotation<L>>::from_leaf(leaf);

        Self { poseidon, max }
    }
}

impl<C, A> Combine<C, A> for PoseidonMaxAnnotation
where
    C: Compound<A>,
    C::Leaf: PoseidonLeaf + Keyed<u64> + Borrow<u64>,
    A: Annotation<C::Leaf>
        + PoseidonTreeAnnotation<C::Leaf>
        + Borrow<Cardinality>
        + Borrow<MaxKey<u64>>,
{
    fn combine(node: &C) -> Self {
        PoseidonMaxAnnotation {
            poseidon: PoseidonAnnotation::combine(node),
            max: MaxKey::combine(node),
        }
    }
}
