// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{
    PoseidonAnnotation, PoseidonTreeAnnotation, PoseidonWalkableAnnotation,
};
use crate::tree::PoseidonLeaf;
use canonical::Canon;
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Annotation, Cardinality, Compound, MaxKey, Step, Walk};
use nstack::NStack;

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

impl<L> PoseidonTreeAnnotation<L> for PoseidonMaxAnnotation
where
    L: PoseidonLeaf,
    L: Borrow<u64>,
{
}

impl<L> Annotation<L> for PoseidonMaxAnnotation
where
    L: PoseidonLeaf,
    L: Borrow<u64>,
{
    fn from_leaf(leaf: &L) -> Self {
        let poseidon = PoseidonAnnotation::from_leaf(leaf);
        let max = <MaxKey<u64> as Annotation<L>>::from_leaf(leaf);

        Self { poseidon, max }
    }
}

#[inline]
fn borrow_u64<A: Borrow<MaxKey<u64>>>(ann: &A) -> u64 {
    match ann.borrow() {
        MaxKey::NegativeInfinity => 0,
        MaxKey::Maximum(m) => *m,
    }
}

impl<C, L, A> PoseidonWalkableAnnotation<C, u64, L, A> for PoseidonMaxAnnotation
where
    L: PoseidonLeaf,
    L: Borrow<u64>,
    C: Clone,
    A: Annotation<L>,
    C: Compound<A>,
{
    fn poseidon_walk(walk: Walk<C, A>, data: u64) -> Step {
        match walk {
            Walk::Leaf(l) if data <= *l.borrow() => Step::Found(l),
            Walk::Node(n) if data <= borrow_u64(n.annotation()) => {
                Step::Into(n)
            }
            _ => Step::Next,
        }
    }
}
