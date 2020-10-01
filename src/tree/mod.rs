// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”

use std::borrow::Borrow;
use std::io;

use dusk_plonk::bls12_381::Scalar as BlsScalar;
use kelvin::annotations::{Cardinality, Combine, Count};
use kelvin::{Branch, BranchMut, ByteHash, Compound, Content, Sink, Source};
use nstack::NStack;

use crate::merkle_lvl_hash::hash::*;
use crate::merkle_proof::poseidon_branch::extend_scalar;
use crate::ARITY;
use crate::{PoseidonBranch, PoseidonLevel, StorageScalar};

/// A zk-friendly datastructure to store elements
///
/// The annotation `AsRef<BlsScalar>` is expected to return the root of the tree
pub struct PoseidonTree<T, A, H>
where
    T: Content<H>,
    T: Clone,
    for<'a> &'a T: Into<StorageScalar>,
    H: ByteHash,
    for<'a> A: From<&'a T>,
    A: Content<H>,
    A: Combine<A>,
    A: Borrow<Cardinality<u64>>,
    A: Borrow<StorageScalar>,
{
    branch_depth: u16,
    inner: NStack<T, A, H>,
}

impl<T, A, H> Clone for PoseidonTree<T, A, H>
where
    T: Content<H>,
    for<'a> &'a T: Into<StorageScalar>,
    H: ByteHash,
    for<'a> A: From<&'a T>,
    A: Content<H>,
    A: Combine<A>,
    A: Borrow<Cardinality<u64>>,
    A: Borrow<StorageScalar>,
{
    fn clone(&self) -> Self {
        PoseidonTree {
            branch_depth: self.branch_depth,
            inner: self.inner.clone(),
        }
    }
}

impl<T, A, H> Content<H> for PoseidonTree<T, A, H>
where
    T: Content<H>,
    for<'a> &'a T: Into<StorageScalar>,
    H: ByteHash,
    for<'a> A: From<&'a T>,
    A: Content<H>,
    A: Combine<A>,
    A: Borrow<Cardinality<u64>>,
    A: Borrow<StorageScalar>,
{
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        self.branch_depth.persist(sink)?;
        self.inner.persist(sink)
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        Ok(PoseidonTree {
            branch_depth: u16::restore(source)?,
            inner: NStack::restore(source)?,
        })
    }
}

impl<T, A, H> PoseidonTree<T, A, H>
where
    T: Content<H>,
    for<'a> &'a T: Into<StorageScalar>,
    H: ByteHash,
    for<'a> A: From<&'a T>,
    A: Content<H>,
    A: Combine<A>,
    A: Borrow<Cardinality<u64>>,
    A: Borrow<StorageScalar>,
{
    /// Constructs a new empty PoseidonTree
    pub fn new(depth: usize) -> Self {
        PoseidonTree {
            branch_depth: depth as u16,
            inner: Default::default(),
        }
    }

    /// Returns the scalar root-hash of the poseidon tree
    ///
    /// This includes padding the value to the correct branch length equivalent
    pub fn root(&self) -> io::Result<BlsScalar> {
        if let Some(ann) = self.inner.annotation() {
            let borrow: &StorageScalar = ann.borrow();
            let scalar: BlsScalar = borrow.clone().into();

            // FIXME, depth could be inferred from the cardinality
            if let Some(branch) = self.get(0)? {
                let depth = branch.levels().len();
                Ok(extend_scalar(scalar, self.branch_depth as usize - depth))
            } else {
                unreachable!("Annotation in empty tree")
            }
        } else {
            // empty case, use an empty level for hashing
            let leaves = [BlsScalar::zero(); ARITY + 1];
            let level = PoseidonLevel { leaves, offset: 0 };
            let root = merkle_level_hash_without_bitflags(&level);
            Ok(extend_scalar(root, self.branch_depth as usize))
        }
    }

    /// Returns a poseidon branch pointing at the specific index
    ///
    /// This includes padding the value to the correct branch length equivalent
    pub fn poseidon_branch(
        &self,
        idx: u64,
    ) -> io::Result<Option<PoseidonBranch>> {
        Ok(self.inner.get(idx)?.map(|ref branch| {
            let mut pbranch: PoseidonBranch = branch.into();
            pbranch.extend(self.branch_depth as usize);
            pbranch
        }))
    }

    /// Push a new item onto the tree
    pub fn push(&mut self, t: T) -> io::Result<u64> {
        let idx = self.inner.count();
        self.inner.push(t)?;
        Ok(idx)
    }

    /// Get a branch reference to the element at index `idx`, if any
    pub fn get(
        &self,
        idx: u64,
    ) -> io::Result<Option<Branch<NStack<T, A, H>, H>>> {
        self.inner.get(idx)
    }

    /// Get a mutable branch reference to the element at index `idx`, if any
    pub fn get_mut(
        &mut self,
        idx: u64,
    ) -> io::Result<Option<BranchMut<NStack<T, A, H>, H>>> {
        self.inner.get_mut(idx)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PoseidonAnnotation;
    use kelvin::Blake2b;

    #[test]
    fn insert() {
        let mut tree = PoseidonTree::<_, PoseidonAnnotation, Blake2b>::new(17);

        for i in 0..128u64 {
            let idx = tree.push(StorageScalar::from(i)).unwrap();
            assert_eq!(idx, i);
        }

        assert!(true)
    }
}
