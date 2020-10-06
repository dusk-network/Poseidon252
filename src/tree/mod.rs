// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::borrow::Borrow;
use std::io;

use crate::{PoseidonBranch, PoseidonLevel, StorageScalar};
use canonical::Canon;
use canonical::Store;
use canonical_derive::Canon;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use kelvin::annotations::{Cardinality, Combine, Count};
use kelvin::{Associative, Branch, BranchMut, Compound, Method};
use nstack::NStack;

/// A zk-friendly datastructure to store elements
///
/// The annotation `AsRef<BlsScalar>` is expected to return the root of the tree
#[derive(Canon)]
pub struct PoseidonTree<T, A, S>
where
    T: Canon<S>,
    for<'a> &'a T: Into<StorageScalar>,
    S: Store,
    for<'a> A: From<&'a T>,
    A: Canon<S>
        + Clone
        + 'static
        + Combine<A>
        + Borrow<Cardinality<u64>>
        + Borrow<StorageScalar>
        + Associative,
{
    branch_depth: u16,
    inner: NStack<T, A, S>,
}

impl<T, A, S> Clone for PoseidonTree<T, A, S>
where
    T: Canon<S>,
    for<'a> &'a T: Into<StorageScalar>,
    S: Store,
    for<'a> A: From<&'a T>,
    A: Canon<S>
        + Clone
        + Combine<A>
        + Borrow<Cardinality<u64>>
        + Borrow<StorageScalar>
        + 'static
        + Associative,
{
    fn clone(&self) -> Self {
        PoseidonTree {
            branch_depth: self.branch_depth,
            inner: self.inner.clone(),
        }
    }
}

impl<T, A, S> PoseidonTree<T, A, S>
where
    T: Canon<S>,
    for<'a> &'a T: Into<StorageScalar>,
    S: Store,
    for<'a> A: From<&'a T>,
    A: Canon<S>
        + Combine<A>
        + Borrow<Cardinality<u64>>
        + Borrow<StorageScalar>
        + Associative,
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
            .get(idx)
            .map_err(|e| {
                io::Error::new(io::ErrorKind::NotFound, format!("{:?}", e))
            })?
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "Couldn't retrieve a Branch",
                )
            })?
            .into();

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
    pub fn push(&mut self, t: T) -> Result<u64, S::Error> {
        let idx = self.inner.count();
        self.inner.push(t)?;
        Ok(idx)
    }

    /// Get a branch reference to the element at index `idx`, if any
    pub fn get<'a>(
        &'a self,
        idx: u64,
    ) -> Result<Option<Branch<NStack<T, A, S>, S>>, S::Error> {
        self.inner.get(idx)
    }

    /// Get a mutable branch reference to the element at index `idx`, if any
    pub fn get_mut(
        &mut self,
        idx: u64,
    ) -> Result<Option<BranchMut<NStack<T, A, S>, S>>, S::Error> {
        self.inner.get_mut(idx)
    }

    /// Reference to the NStack inner implementation
    pub fn inner(&self) -> &NStack<T, A, S> {
        &self.inner
    }

    /// Mutable reference to the NStack inner implementation
    pub fn inner_mut(&mut self) -> &mut NStack<T, A, S> {
        &mut self.inner
    }

    /// Perform a filtered iteration over the tree
    pub fn iter_filtered<M: Method<NStack<T, A, S>, S>>(
        &self,
        filter: M,
    ) -> Result<PoseidonTreeIterator<T, A, S, M>, S::Error> {
        PoseidonTreeIterator::new(&self.inner, filter)
    }
}

/// Iterator created from a PoseidonTree with a provided `Method` to filter it
///
/// The returned elements are results of the leaves
///
/// Every iteration relies on I/O operations; this way, they can fail
pub struct PoseidonTreeIterator<'a, T, A, S, M>
where
    T: Canon<S>,
    for<'b> A: From<&'b T>,
    A: Combine<A> + Canon<S> + 'static + Associative,
    S: Store,
    M: Method<NStack<T, A, S>, S>,
{
    filter: M,
    branch: Option<Branch<'a, NStack<T, A, S>, S>>,
}

impl<'a, T, A, S, M> PoseidonTreeIterator<'a, T, A, S, M>
where
    T: Canon<S>,
    for<'b> A: From<&'b T>,
    A: Combine<A> + Canon<S> + 'static + Associative,
    S: Store,
    M: Method<NStack<T, A, S>, S>,
{
    /// Constructor
    pub fn new(
        tree: &'a NStack<T, A, S>,
        mut filter: M,
    ) -> Result<Self, S::Error> {
        tree.search(&mut filter)
            .map(|branch| Self { filter, branch })
    }
}

impl<'a, T, A, S, M> Iterator for PoseidonTreeIterator<'a, T, A, S, M>
where
    T: Canon<S>,
    for<'b> A: From<&'b T>,
    A: Combine<A> + Canon<S> + Associative,
    S: Store,
    M: Method<NStack<T, A, S>, S>,
{
    type Item = Result<T, S::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let note = match &self.branch {
            Some(branch) => (*branch).clone(),
            None => return None,
        };

        let branch = match self.branch.take() {
            Some(b) => b,
            None => return Some(Err(canonical::InvalidEncoding.into())),
        };

        self.branch = match branch.search(&mut self.filter) {
            Ok(b) => b,
            Err(_e) => return Some(Err(canonical::InvalidEncoding.into())),
        };

        Some(Ok(note))
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
        assert_eq!(tree.root()?, pbranch.root);
        Ok(())
    }
}
