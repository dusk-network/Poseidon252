// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::borrow::Borrow;
use std::io;

use dusk_plonk::bls12_381::Scalar as BlsScalar;
use kelvin::annotations::{Cardinality, Combine, Count};
use kelvin::{Branch, BranchMut, ByteHash, Compound, Content, Sink, Source};
use nstack::NStack;

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
        let first_level: A = self.inner().annotation().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Kelvin shouldn't fail at reading annotations",
            )
        })?;
        let storage_scalar: &StorageScalar = first_level.borrow();
        Ok(storage_scalar.to_owned().into())
    }

    /// Returns a poseidon branch pointing at the specific index
    ///
    /// This includes padding the value to the correct branch length equivalent
    pub fn poseidon_branch(
        &self,
        idx: u64,
    ) -> io::Result<Option<PoseidonBranch>> {
        // Try to get the PoseidonBranch from the tree.
        let mut pbranch: PoseidonBranch = self
            .inner
            .get(idx)?
            .map(|ref branch| branch.into())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Couldn't retrieve a branch from the tree",
                )
            })?;

        // We check if the branch requires padding, in which case, we add as many padding levels as it's
        // needed in order to have the correct branch padding for the
        // merkle opening proofs.
        //
        // The values added in the padding levels do not matter at all for Scalar merkle opening proofs since
        // they aren't used/required. These levels are added so that the circuits that require the
        // `merkle_opening_gadget` fn do not have variadic sizes. But the operations performed for these levels
        // are not constrained (they can be considered dummy ops just to pad the circuits).
        if self.branch_depth as usize > pbranch.levels.len() {
            pbranch.padding_levels.extend(vec![
                PoseidonLevel::default();
                self.branch_depth as usize
                    - pbranch.levels.len()
            ]);
        }

        Ok(Some(pbranch))
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

    /// Reference to the NStack inner implementation
    pub fn inner(&self) -> &NStack<T, A, H> {
        &self.inner
    }

    /// Mutable reference to the NStack inner implementation
    pub fn inner_mut(&mut self) -> &mut NStack<T, A, H> {
        &mut self.inner
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{PoseidonAnnotation, PoseidonBranch};
    use kelvin::Blake2b;

    #[test]
    fn insert() -> io::Result<()> {
        let mut tree = PoseidonTree::<_, PoseidonAnnotation, Blake2b>::new(17);

        for i in 0..128u64 {
            let idx = tree.push(StorageScalar::from(i))?;
            assert_eq!(idx, i);
        }
        Ok(())
    }

    #[test]
    fn root_consistency_branch_tree() -> io::Result<()> {
        let mut tree = PoseidonTree::<_, PoseidonAnnotation, Blake2b>::new(17);
        let idx = tree.push(StorageScalar::from(55u64))?;
        let branch = tree.get(idx)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Kelvin shouldn't fail at reading annotations",
            )
        })?;
        let pbranch = PoseidonBranch::from(&branch);
        assert_eq!(tree.root()?, pbranch.root)
    }
}
