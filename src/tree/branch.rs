// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonLeaf;

use crate::tree::PoseidonAnnotation;

use alloc::vec::Vec;

use core::borrow::Borrow;
use core::iter;
use core::ops::Deref;

use dusk_bls12_381::BlsScalar;
use dusk_hades::{ScalarStrategy, Strategy};
use microkelvin::Branch;
use nstack::annotation::Keyed;
use nstack::NStack;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Represents a level of a branch on a given depth
#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(CheckBytes))
)]
pub struct PoseidonLevel {
    level: [BlsScalar; dusk_hades::WIDTH],
    index: u64,
}

impl PoseidonLevel {
    /// Represents the offset of a node for a given path produced by a branch
    /// in a merkle opening
    ///
    /// The first position in a level set is represented as offset `1` because
    /// internally the hades permutation prepend the bitflags for merkle opening
    /// consistency
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Represents the current level offset as a bitflag
    ///
    /// The LSB (least significant bit) represents the offset `1`. Any increment
    /// on the offset will left shift this flag by `1`.
    pub const fn offset_flag(&self) -> u64 {
        1 << (self.index - 1)
    }
}

impl Deref for PoseidonLevel {
    type Target = BlsScalar;

    fn deref(&self) -> &Self::Target {
        &self.level[self.index as usize]
    }
}

impl AsRef<[BlsScalar]> for PoseidonLevel {
    fn as_ref(&self) -> &[BlsScalar] {
        &self.level
    }
}

/// Represents a full path for a merkle opening
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(CheckBytes))
)]
pub struct PoseidonBranch<const DEPTH: usize> {
    path: Vec<PoseidonLevel>,
}

impl<const DEPTH: usize> PoseidonBranch<DEPTH> {
    /// Root representation when the tree is empty
    pub const NULL_ROOT: BlsScalar = BlsScalar::zero();

    /// Represents the root for a given path of an opening over a subtree
    pub fn root(&self) -> &BlsScalar {
        self.path
            .last()
            .map(|l| l.deref())
            .unwrap_or(&Self::NULL_ROOT)
    }
}

impl<const DEPTH: usize> Deref for PoseidonBranch<DEPTH> {
    type Target = BlsScalar;

    fn deref(&self) -> &Self::Target {
        self.path[0].deref()
    }
}

impl<const DEPTH: usize> Default for PoseidonBranch<DEPTH> {
    fn default() -> Self {
        let path = iter::repeat(PoseidonLevel::default())
            .take(DEPTH + 1)
            .collect();

        Self { path }
    }
}

impl<const DEPTH: usize> AsRef<[PoseidonLevel]> for PoseidonBranch<DEPTH> {
    fn as_ref(&self) -> &[PoseidonLevel] {
        &self.path
    }
}

impl<L, K, const DEPTH: usize>
    From<&Branch<'_, NStack<L, PoseidonAnnotation<K>>, PoseidonAnnotation<K>>>
    for PoseidonBranch<DEPTH>
where
    L: PoseidonLeaf + Keyed<K>,
    K: Clone + PartialOrd,
{
    fn from(
        b: &Branch<'_, NStack<L, PoseidonAnnotation<K>>, PoseidonAnnotation<K>>,
    ) -> Self {
        let mut branch = PoseidonBranch::default();
        let mut depth = 0;

        b.levels()
            .iter()
            .rev()
            .zip(branch.path.iter_mut())
            .for_each(|(l, b)| {
                depth += 1;
                b.index = l.index() as u64 + 1;

                let mut flag = 1;
                let mut mask = 0;

                match &**l {
                    NStack::Leaf(l) => l
                        .iter()
                        .zip(b.level.iter_mut().skip(1))
                        .for_each(|(leaf, l)| {
                            if let Some(leaf) = leaf {
                                mask |= flag;
                                *l = leaf.poseidon_hash();
                            }

                            flag <<= 1;
                        }),
                    NStack::Node(n) => n
                        .iter()
                        .zip(b.level.iter_mut().skip(1))
                        .for_each(|(node, l)| {
                            if let Some(annotated) = node {
                                let anno = annotated.anno();
                                let anno = &*anno;

                                mask |= flag;

                                *l = *anno.borrow();
                            }

                            flag <<= 1;
                        }),
                }

                b.level[0] = BlsScalar::from(mask);
            });

        if depth >= DEPTH {
            return branch;
        }

        let flag = BlsScalar::one();
        let level = branch.path[depth - 1].level;
        let mut perm = [BlsScalar::zero(); dusk_hades::WIDTH];

        let mut h = ScalarStrategy::new();
        branch.path.iter_mut().skip(depth).fold(level, |l, b| {
            perm.copy_from_slice(&l);
            h.perm(&mut perm);

            b.index = 1;
            b.level[0] = flag;
            b.level[1] = perm[1];

            b.level
        });

        branch
    }
}
