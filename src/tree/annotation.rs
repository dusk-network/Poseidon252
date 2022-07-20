// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::tree::PoseidonLeaf;

use core::borrow::Borrow;

use dusk_bls12_381::BlsScalar;
use dusk_hades::{ScalarStrategy, Strategy};

use nstack::annotation::{Cardinality, Keyed, MaxKey};
use nstack::NStack;
use ranno::Annotation;

/// Extends the standard [`PoseidonAnnotation`] with an annotation that holds an
/// agnostic maximum value.
#[derive(Debug, Clone, Default)]
pub struct PoseidonAnnotation<K> {
    poseidon_root: BlsScalar,
    cardinality: Cardinality,
    max_key: MaxKey<K>,
}

impl<K> Borrow<BlsScalar> for PoseidonAnnotation<K> {
    fn borrow(&self) -> &BlsScalar {
        &self.poseidon_root
    }
}

impl<K> Borrow<Cardinality> for PoseidonAnnotation<K> {
    fn borrow(&self) -> &Cardinality {
        &self.cardinality
    }
}

impl<K> Borrow<MaxKey<K>> for PoseidonAnnotation<K> {
    fn borrow(&self) -> &MaxKey<K> {
        &self.max_key
    }
}

impl<L, K> Annotation<NStack<L, PoseidonAnnotation<K>>>
    for PoseidonAnnotation<K>
where
    L: PoseidonLeaf + Keyed<K>,
    K: Clone + PartialOrd,
{
    fn from_child(stack: &NStack<L, PoseidonAnnotation<K>>) -> Self {
        let mut perm = [BlsScalar::zero(); dusk_hades::WIDTH];
        let mut flag = 1;
        let mut mask = 0;
        let mut cardinality = 0;
        let mut max_key = MaxKey::<K>::NegativeInfinity;

        match stack {
            NStack::Leaf(leaf) => {
                for (i, l) in leaf.iter().enumerate() {
                    if let Some(l) = l {
                        mask |= flag;
                        perm[i + 1] = l.poseidon_hash();
                        cardinality += 1;

                        let key = l.key();
                        if &max_key < key {
                            max_key = MaxKey::Maximum(key.clone());
                        }
                    }
                    flag <<= 1;
                }
            }
            NStack::Node(node) => {
                for (i, n) in node.iter().enumerate() {
                    if let Some(annotated) = n {
                        mask |= flag;
                        let anno = annotated.anno();
                        let anno = &*anno;

                        perm[i + 1] = anno.poseidon_root;
                        cardinality += *anno.cardinality;

                        if max_key < anno.max_key {
                            max_key = anno.max_key.clone();
                        }
                    }
                    flag <<= 1;
                }
            }
        }

        perm[0] = BlsScalar::from(mask);
        ScalarStrategy::new().perm(&mut perm);
        let poseidon_root = perm[1];

        Self {
            cardinality: cardinality.into(),
            poseidon_root,
            max_key,
        }
    }
}
