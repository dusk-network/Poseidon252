// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonTreeAnnotation;
use crate::tree::PoseidonLeaf;
use canonical::{Canon, Store};
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_plonk::prelude::*;
use hades252::{ScalarStrategy, Strategy};
use microkelvin::{Annotation, Cardinality};
use nstack::NStack;

/// A microkelvin annotation with the minimum data for a functional poseidon tree
///
/// The recommended usage for extended annotations for poseidon trees is to have
/// this structure as attribute of the concrete annotation, and reflect the borrows
/// of the cardinality and scalar to the poseidon annotation implementation.
#[derive(Debug, Clone, Canon)]
pub struct PoseidonAnnotation {
    cardinality: Cardinality,
    poseidon_root: BlsScalar,
}

impl PoseidonAnnotation {
    /// Create a new poseidon annotation from a generic node implementation
    pub fn from_generic_node<L, A, S>(node: &NStack<L, A, S>) -> Self
    where
        L: PoseidonLeaf<S>,
        A: PoseidonTreeAnnotation<L, S>,
        S: Store,
    {
        let cardinality =
            <Cardinality as Annotation<NStack<L, A, S>, S>>::from_node(node);

        let mut perm = [BlsScalar::zero(); hades252::WIDTH];
        let mut flag = 1;
        let mut mask = 0;

        match node {
            NStack::Leaf(l) => {
                l.iter().zip(perm.iter_mut().skip(1)).for_each(|(l, p)| {
                    if let Some(l) = l {
                        mask |= flag;
                        *p = l.poseidon_hash();
                    }

                    flag <<= 1;
                });
            }

            NStack::Node(n) => {
                n.iter().zip(perm.iter_mut().skip(1)).for_each(|(n, p)| {
                    if let Some(n) = n {
                        mask |= flag;
                        *p = *n.annotation().borrow();
                    }

                    flag <<= 1;
                });
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

impl<L, S> PoseidonTreeAnnotation<L, S> for PoseidonAnnotation
where
    L: PoseidonLeaf<S>,
    S: Store,
{
}

impl<L, S> Annotation<NStack<L, PoseidonAnnotation, S>, S>
    for PoseidonAnnotation
where
    L: PoseidonLeaf<S>,
    S: Store,
{
    fn identity() -> Self {
        let cardinality = <Cardinality as Annotation<
            NStack<L, PoseidonAnnotation, S>,
            S,
        >>::identity();
        let poseidon_root = BlsScalar::zero();

        Self {
            cardinality,
            poseidon_root,
        }
    }

    fn from_leaf(leaf: &L) -> Self {
        let cardinality = <Cardinality as Annotation<
            NStack<L, PoseidonAnnotation, S>,
            S,
        >>::from_leaf(leaf);
        let poseidon_root = leaf.poseidon_hash();

        Self {
            cardinality,
            poseidon_root,
        }
    }

    fn from_node(node: &NStack<L, PoseidonAnnotation, S>) -> Self {
        Self::from_generic_node(node)
    }
}
