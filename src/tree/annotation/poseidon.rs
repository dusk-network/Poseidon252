// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonTreeAnnotation;
use crate::tree::PoseidonLeaf;
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use dusk_hades::{ScalarStrategy, Strategy};
use microkelvin::{Annotation, Cardinality, Combine, Compound, IterChild};

/// A microkelvin annotation with the minimum data for a functional poseidon tree
///
/// The recommended usage for extended annotations for poseidon trees is to have
/// this structure as attribute of the concrete annotation, and reflect the borrows
/// of the cardinality and scalar to the poseidon annotation implementation.
#[derive(Debug, Clone, Canon, Default)]
pub struct PoseidonAnnotation {
    cardinality: Cardinality,
    poseidon_root: BlsScalar,
}

impl PoseidonAnnotation {
    /// Create a new poseidon annotation from a generic node implementation
    pub fn from_generic_node<C, A>(node: &C) -> Self
    where
        C::Leaf: PoseidonLeaf,
        A: PoseidonTreeAnnotation<C::Leaf>,
        A: Annotation<C::Leaf>,
        C: Compound<A>,
    {
        let cardinality = Cardinality::combine(node);

        let mut perm = [BlsScalar::zero(); dusk_hades::WIDTH];
        let mut flag = 1;
        let mut mask = 0;

        for (i, child) in node.children().enumerate() {
            match child {
                IterChild::Leaf(l) => {
                    mask |= flag;
                    perm[i + 1] = *l.poseidon_hash();

                    flag <<= 1;
                }

                IterChild::Node(n) => {
                    mask |= flag;
                    perm[i + 1] = *n.annotation().borrow();

                    flag <<= 1;
                }
            }
        }

        perm[0] = BlsScalar::from(mask);
        ScalarStrategy::new().perm(&mut perm);
        let poseidon_root = perm[1];

        Self {
            cardinality,
            poseidon_root,
        }
    }

    /// Return the scalar representation of the root of the annotated subtree
    pub fn poseidon_root(&self) -> &BlsScalar {
        &self.poseidon_root
    }
}

impl Borrow<Cardinality> for PoseidonAnnotation {
    fn borrow(&self) -> &Cardinality {
        &self.cardinality
    }
}

impl Borrow<BlsScalar> for PoseidonAnnotation {
    fn borrow(&self) -> &BlsScalar {
        &self.poseidon_root
    }
}

impl<L> Annotation<L> for PoseidonAnnotation
where
    L: PoseidonLeaf,
{
    fn from_leaf(leaf: &L) -> Self {
        let cardinality = Cardinality::from_leaf(leaf);
        let poseidon_root = *leaf.poseidon_hash();

        Self {
            cardinality,
            poseidon_root,
        }
    }
}

impl<C, A> Combine<C, A> for PoseidonAnnotation
where
    C: Compound<A>,
    C::Leaf: PoseidonLeaf,
    A: Annotation<C::Leaf>
        + PoseidonTreeAnnotation<C::Leaf>
        + Borrow<Cardinality>,
{
    fn combine(node: &C) -> Self {
        PoseidonAnnotation::from_generic_node(node)
    }
}
