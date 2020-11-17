// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{
    PoseidonAnnotation, PoseidonTreeAnnotation, PoseidonWalkableAnnotation,
};
use crate::tree::PoseidonLeaf;
use canonical::{Canon, Store};
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Annotation, Cardinality, Compound, Max, Step, Walk};
use nstack::NStack;

/// Extends the standard [`PoseidonAnnotation`] with an annotation that holds an agnostic maximum
/// value
///
/// This maximum value is representes as `u64`, and the tree is iterable over it
#[derive(Debug, Clone, Canon)]
pub struct PoseidonMaxAnnotation {
    poseidon: PoseidonAnnotation,
    max: Max<u64>,
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

impl Borrow<u64> for PoseidonMaxAnnotation {
    fn borrow(&self) -> &u64 {
        match &self.max {
            Max::Maximum(m) => m,
            Max::NegativeInfinity => &u64::min_value(),
        }
    }
}

impl<L, S> PoseidonTreeAnnotation<L, S> for PoseidonMaxAnnotation
where
    L: PoseidonLeaf<S>,
    L: Borrow<u64>,
    S: Store,
{
}

impl<L, S> Annotation<NStack<L, PoseidonMaxAnnotation, S>, S>
    for PoseidonMaxAnnotation
where
    L: PoseidonLeaf<S>,
    L: Borrow<u64>,
    S: Store,
{
    fn identity() -> Self {
        let poseidon = <PoseidonAnnotation as Annotation<
            NStack<L, PoseidonAnnotation, S>,
            S,
        >>::identity();
        let max = <Max<u64> as Annotation<NStack<L, Self, S>, S>>::identity();

        Self { poseidon, max }
    }

    fn from_leaf(leaf: &L) -> Self {
        let poseidon = PoseidonAnnotation::from_leaf(leaf);
        let max =
            <Max<u64> as Annotation<NStack<L, Self, S>, S>>::from_leaf(leaf);

        Self { poseidon, max }
    }

    fn from_node(node: &NStack<L, PoseidonMaxAnnotation, S>) -> Self {
        let poseidon = PoseidonAnnotation::from_generic_node(node);
        let max =
            <Max<u64> as Annotation<NStack<L, Self, S>, S>>::from_node(node);

        Self { poseidon, max }
    }
}

impl<C, L, S> PoseidonWalkableAnnotation<C, u64, L, S> for PoseidonMaxAnnotation
where
    L: PoseidonLeaf<S>,
    L: Borrow<u64>,
    C: Clone,
    C::Annotation: Annotation<C, S>,
    C: Compound<S, Leaf = L, Annotation = Self>,
    S: Store,
{
    fn poseidon_walk(walk: Walk<'_, C, S>, data: u64) -> Step<'_, C, S> {
        match walk {
            Walk::Leaf(l) if data <= *l.borrow() => Step::Found(l),
            Walk::Node(n) if data <= *n.annotation().borrow() => Step::Into(n),
            _ => Step::Next,
        }
    }
}
