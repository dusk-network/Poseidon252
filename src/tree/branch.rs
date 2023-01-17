// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonLeaf;

use crate::tree::PoseidonAnnotation;

use core::borrow::Borrow;
use core::ops::Deref;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
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
    pub(crate) level: [BlsScalar; dusk_hades::WIDTH],
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

impl Serializable<{ BlsScalar::SIZE * dusk_hades::WIDTH + u64::SIZE }>
    for PoseidonLevel
{
    type Error = dusk_bytes::Error;

    fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut bytes = &buf[..];

        let mut level = [BlsScalar::zero(); dusk_hades::WIDTH];
        for scalar in level.iter_mut() {
            *scalar = BlsScalar::from_reader(&mut bytes)?;
        }

        let index = u64::from_reader(&mut bytes)?;

        Ok(Self { level, index })
    }

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];

        for (i, scalar) in self.level.iter().enumerate() {
            buf[i * BlsScalar::SIZE..(i + 1) * BlsScalar::SIZE]
                .copy_from_slice(&scalar.to_bytes());
        }

        buf[BlsScalar::SIZE * dusk_hades::WIDTH..]
            .copy_from_slice(&self.index.to_bytes());

        buf
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
#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(CheckBytes))
)]
pub struct PoseidonBranch<const DEPTH: usize> {
    pub(crate) path: [PoseidonLevel; DEPTH],
    root: BlsScalar,
}

// This macro is necessary due to the fact that `generic_const_exprs`, is still
// unstable. It should remain here until this is completed:
// https://github.com/rust-lang/rust/issues/76560
macro_rules! serializable_branch {
    ($($depth:literal),+) => {
        $(impl Serializable<{ PoseidonLevel::SIZE * $depth + BlsScalar::SIZE }>
            for PoseidonBranch<$depth>
        {
            type Error = dusk_bytes::Error;

            fn from_bytes(buf: &[u8; Self::SIZE]) -> Result<Self, Self::Error>
            where
                Self: Sized,
            {
                let mut bytes = &buf[..];

                let mut path = [PoseidonLevel::default(); $depth];
                for level in path.iter_mut() {
                    *level = PoseidonLevel::from_reader(&mut bytes)?;
                }

                let root = BlsScalar::from_reader(&mut bytes)?;

                Ok(Self { path, root })
            }

            fn to_bytes(&self) -> [u8; Self::SIZE] {
                let mut buf = [0u8; Self::SIZE];

                for (i, level) in self.path.iter().enumerate() {
                    buf[i * PoseidonLevel::SIZE..(i + 1) * PoseidonLevel::SIZE]
                        .copy_from_slice(&level.to_bytes());
                }

                buf[PoseidonLevel::SIZE * $depth..]
                    .copy_from_slice(&self.root.to_bytes());

                buf
            }
        })*
    };
}

serializable_branch!(
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 64, 128, 256, 512, 1024, 2048
);

impl<const DEPTH: usize> PoseidonBranch<DEPTH> {
    /// Root representation when the tree is empty
    pub const NULL_ROOT: BlsScalar = BlsScalar::zero();

    /// Represents the root for a given path of an opening over a subtree
    pub fn root(&self) -> &BlsScalar {
        &self.root
    }
}

impl<const DEPTH: usize> Default for PoseidonBranch<DEPTH> {
    fn default() -> Self {
        Self {
            path: [PoseidonLevel::default(); DEPTH],
            root: BlsScalar::default(),
        }
    }
}

impl<const DEPTH: usize> Deref for PoseidonBranch<DEPTH> {
    type Target = BlsScalar;

    fn deref(&self) -> &Self::Target {
        self.path[0].deref()
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
        let mut path = [PoseidonLevel::default(); DEPTH];

        b.levels().iter().rev().zip(path.iter_mut()).for_each(
            |(nstack_level, poseidon_level)| {
                poseidon_level.index = nstack_level.index() as u64 + 1;

                let mut flag = 1;
                let mut mask = 0;

                match &**nstack_level {
                    NStack::Leaf(l) => l
                        .iter()
                        .zip(poseidon_level.level.iter_mut().skip(1))
                        .for_each(|(leaf, l)| {
                            if let Some(leaf) = leaf {
                                mask |= flag;
                                *l = leaf.poseidon_hash();
                            }

                            flag <<= 1;
                        }),
                    NStack::Node(n) => n
                        .iter()
                        .zip(poseidon_level.level.iter_mut().skip(1))
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

                poseidon_level.level[0] = BlsScalar::from(mask);
            },
        );

        // If the nstack is smaller than the poseidon tree then the we need to
        // populate the remaining levels of the tree.
        let nstack_depth = b.levels().len();
        let flag = BlsScalar::one();

        if nstack_depth < DEPTH {
            let level = path[nstack_depth - 1].level;
            let mut perm = [BlsScalar::zero(); dusk_hades::WIDTH];

            let mut h = ScalarStrategy::new();

            path.iter_mut().skip(nstack_depth).fold(level, |l, b| {
                perm.copy_from_slice(&l);
                h.perm(&mut perm);

                b.index = 1;
                b.level[0] = flag;
                b.level[1] = perm[1];

                b.level
            });
        }

        // TODO: The amount of repetition here hints at the fact that hashing
        //  should be more ergonomic.

        // Calculate the root
        let mut perm = [BlsScalar::zero(); dusk_hades::WIDTH];
        let mut h = ScalarStrategy::new();

        perm.copy_from_slice(&path[DEPTH - 1].level);
        perm[0] = flag;
        h.perm(&mut perm);

        PoseidonBranch {
            path,
            root: perm[1],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tree::{PoseidonBranch, PoseidonLevel};

    use dusk_bls12_381::BlsScalar;
    use dusk_bytes::Serializable;

    #[test]
    fn branch_serde() {
        type Branch = PoseidonBranch<17>;

        let mut poseidon_level = PoseidonLevel {
            index: 0xbeef,
            ..Default::default()
        };
        poseidon_level.level[3] = BlsScalar::from(42);

        let mut branch = Branch {
            root: BlsScalar::from(4),
            ..Default::default()
        };
        branch.path[7] = poseidon_level;

        let branch_bytes = branch.to_bytes();
        let deserialized_branch = Branch::from_bytes(&branch_bytes)
            .expect("Deserializing should succeed");

        assert_eq!(branch.root, deserialized_branch.root);
        for (level, deserialized_level) in
            branch.path.iter().zip(&deserialized_branch.path)
        {
            assert_eq!(level.index, deserialized_level.index);
            for (scalar, deserialized_scalar) in
                level.level.iter().zip(&deserialized_level.level)
            {
                assert_eq!(scalar, deserialized_scalar);
            }
        }
    }
}
