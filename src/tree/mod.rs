// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::borrow::Borrow;
use std::io;

use dusk_plonk::bls12_381::Scalar as BlsScalar;
use kelvin::annotations::{Cardinality, Combine, Count};
use kelvin::{
    Branch, BranchMut, ByteHash, Compound, Content, Method, Sink, Source,
};
use nstack::NStack;

use crate::{PoseidonBranch, StorageScalar};

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
        let branch = self
            .get(0)?
            .unwrap_or(PoseidonBranch::mock(&[], self.branch_depth as usize));

        Ok(branch.root())
    }

    /// Returns a poseidon branch pointing at the specific index
    ///
    /// This includes padding the value to the correct branch length equivalent.
    ///
    /// This function doesn't return the default `get` implementation from
    /// Kelvin because for Poseidon the height is fixed, and for kelvin it
    /// depends on the number of elements appended to the tree.
    pub fn get(&self, idx: u64) -> io::Result<Option<PoseidonBranch>> {
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

        pbranch.extend(self.branch_depth as usize);

        Ok(Some(pbranch))
    }

    /// Push a new item onto the tree
    pub fn push(&mut self, t: T) -> io::Result<u64> {
        let idx = self.inner.count();
        self.inner.push(t)?;
        Ok(idx)
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

    /// Perform a filtered iteration over the tree
    pub fn iter_filtered<M: Method<NStack<T, A, H>, H>>(
        &self,
        filter: M,
    ) -> io::Result<PoseidonTreeIterator<T, A, H, M>> {
        PoseidonTreeIterator::new(&self.inner, filter)
    }
}

/// Iterator created from a PoseidonTree with a provided `Method` to filter it
///
/// The returned elements are results of the leaves
///
/// Every iteration relies on I/O operations; this way, they can fail
pub struct PoseidonTreeIterator<'a, T, A, H, M>
where
    T: Content<H>,
    for<'b> A: From<&'b T>,
    A: Content<H>,
    A: Combine<A>,
    H: ByteHash,
    M: Method<NStack<T, A, H>, H>,
{
    filter: M,
    branch: Option<Branch<'a, NStack<T, A, H>, H>>,
}

impl<'a, T, A, H, M> PoseidonTreeIterator<'a, T, A, H, M>
where
    T: Content<H>,
    for<'b> A: From<&'b T>,
    A: Content<H>,
    A: Combine<A>,
    H: ByteHash,
    M: Method<NStack<T, A, H>, H>,
{
    /// Constructor
    pub fn new(tree: &'a NStack<T, A, H>, mut filter: M) -> io::Result<Self> {
        tree.search(&mut filter)
            .map(|branch| Self { filter, branch })
    }
}

impl<'a, T, A, H, M> Iterator for PoseidonTreeIterator<'a, T, A, H, M>
where
    T: Content<H>,
    for<'b> A: From<&'b T>,
    A: Content<H>,
    A: Combine<A>,
    H: ByteHash,
    M: Method<NStack<T, A, H>, H>,
{
    type Item = io::Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        let note = match &self.branch {
            Some(branch) => (*branch).clone(),
            None => return None,
        };

        let branch = match self.branch.take() {
            Some(b) => b,
            None => {
                return Some(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unexpected null!",
                )))
            }
        };

        self.branch = match branch.search(&mut self.filter) {
            Ok(b) => b,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok(note))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::merkle_lvl_hash::hash::merkle_level_hash;
    use crate::{PoseidonAnnotation, PoseidonBranch, ARITY};
    use kelvin::Blake2b;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

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
        let branch = tree.inner().get(idx)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Kelvin shouldn't fail at reading annotations",
            )
        })?;

        let pbranch = PoseidonBranch::from(&branch);
        // Kelvin root currently returns a minimum number of hashed leaves
        //
        // For a single leaf, it should calculate a single hash, so its root
        // must be different than the poseidon fixed height tree
        assert_ne!(tree.root()?, pbranch.root);

        Ok(())
    }

    #[test]
    fn tree_precalculated_root() -> io::Result<()> {
        let mut rng_seed = StdRng::seed_from_u64(3498304u64);
        let rng = &mut rng_seed;

        let mut perm = [None; ARITY];
        let depth = 17;

        for i in &[
            1,
            ARITY - 1,
            ARITY,
            ARITY + 1,
            ARITY + 2,
            10,
            100,
            1000,
            10000,
        ] {
            // Create a set of random leaves
            let leaves = (0..*i)
                .map(|_| BlsScalar::random(rng))
                .collect::<Vec<BlsScalar>>();

            // Split in chunks of arity size and calculate their hashes
            //
            // Repeat the process until we find the root
            let mut d = 1;
            let mut levels = leaves.clone();
            loop {
                levels = levels
                    .chunks(ARITY)
                    .map(|c| {
                        for p in perm.iter_mut() {
                            *p = None;
                        }

                        for i in 0..c.len() {
                            perm[i].replace(c[i]);
                        }

                        merkle_level_hash(&perm)
                    })
                    .collect::<Vec<BlsScalar>>();

                d += 1;
                if levels.len() == 1 {
                    break;
                }
            }

            // Fill the remainder levels and get the root
            let mut root = levels[0];
            while d < depth {
                root = merkle_level_hash(&[Some(root)]);
                d += 1;
            }

            // Insert the leaves on the tree
            let mut tree =
                PoseidonTree::<_, PoseidonAnnotation, Blake2b>::new(17);
            for l in leaves.into_iter() {
                tree.push(l.into())?;
            }

            // Fetch the root and compare
            let branch = tree
                .get(0)?
                .expect("The element was inserted and should be present");

            let tree_root = branch.root();
            assert_eq!(root, tree_root);
        }

        Ok(())
    }
}
