// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{PoseidonAnnotation, PoseidonTreeAnnotation};
use crate::tree::PoseidonLeaf;
use canonical::Canon;
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Annotation, Cardinality, Combine, Compound, Keyed, MaxKey};

/// Extends the standard [`PoseidonAnnotation`] with an annotation that holds an agnostic maximum
/// value
///
/// This maximum value is representes as `u64`, and the tree is iterable over it
#[derive(Debug, Clone, Canon, Default)]
pub struct PoseidonMaxAnnotation<K>
where
    K: Canon + Default + Clone + Ord,
{
    poseidon: PoseidonAnnotation,
    max: MaxKey<K>,
}

impl<K> Borrow<Cardinality> for PoseidonMaxAnnotation<K>
where
    K: Canon + Default + Clone + Ord,
{
    fn borrow(&self) -> &Cardinality {
        self.poseidon.borrow()
    }
}

impl<K> Borrow<BlsScalar> for PoseidonMaxAnnotation<K>
where
    K: Canon + Default + Clone + Ord,
{
    fn borrow(&self) -> &BlsScalar {
        self.poseidon.borrow()
    }
}

impl<K> Borrow<MaxKey<K>> for PoseidonMaxAnnotation<K>
where
    K: Canon + Default + Clone + Ord,
{
    fn borrow(&self) -> &MaxKey<K> {
        &self.max
    }
}

impl<L, K> Annotation<L> for PoseidonMaxAnnotation<K>
where
    L: PoseidonLeaf,
    L: Borrow<u64>,
    L: Keyed<K>,
    K: Canon + Default + Clone + Ord,
{
    fn from_leaf(leaf: &L) -> Self {
        let poseidon = PoseidonAnnotation::from_leaf(leaf);
        let max = <MaxKey<K> as Annotation<L>>::from_leaf(leaf);

        Self { poseidon, max }
    }
}

impl<C, A, K> Combine<C, A> for PoseidonMaxAnnotation<K>
where
    C: Compound<A>,
    C::Leaf: PoseidonLeaf + Keyed<K> + Borrow<u64>,
    A: Annotation<C::Leaf>
        + PoseidonTreeAnnotation<C::Leaf>
        + Borrow<Cardinality>
        + Borrow<MaxKey<K>>,
    K: Canon + Default + Clone + Ord,
{
    fn combine(node: &C) -> Self {
        PoseidonMaxAnnotation {
            poseidon: PoseidonAnnotation::combine(node),
            max: MaxKey::combine(node),
        }
    }
}

impl<L, K> PoseidonTreeAnnotation<L> for PoseidonMaxAnnotation<K>
where
    L: PoseidonLeaf + Borrow<u64> + Keyed<K>,
    K: Canon + Default + Clone + Ord,
{
}
