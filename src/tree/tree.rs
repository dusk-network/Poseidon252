// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{PoseidonBranch, PoseidonLeaf, PoseidonTreeAnnotation};
use crate::Error;
use canonical::CanonError;
use canonical_derive::Canon;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Branch, Cardinality, Combine, Nth, Walker};
use nstack::NStack;

/// Represents a Merkle Tree with a given depth that will be calculated using
/// the Poseidon Hash technique.
#[derive(Debug, Clone, Canon)]
pub struct PoseidonTree<L, A, const DEPTH: usize>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
{
    inner: NStack<L, A>,
}

impl<L, A, const DEPTH: usize> AsRef<NStack<L, A>> for PoseidonTree<L, A, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
{
    fn as_ref(&self) -> &NStack<L, A> {
        &self.inner
    }
}

impl<L, A, const DEPTH: usize> AsMut<NStack<L, A>> for PoseidonTree<L, A, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
{
    fn as_mut(&mut self) -> &mut NStack<L, A> {
        &mut self.inner
    }
}

impl<L, A, const DEPTH: usize> Default for PoseidonTree<L, A, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
{
    fn default() -> Self {
        PoseidonTree::new()
    }
}

impl<L, A, const DEPTH: usize> PoseidonTree<L, A, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
{
    /// Creates a new poseidon tree
    pub fn new() -> Self {
        let inner = NStack::new();

        Self { inner }
    }

    /// Append a leaf to the tree. Return the index of the appended leaf.
    pub fn push(&mut self, mut leaf: L) -> Result<u64, Error> {
        let size = Cardinality::combine(&self.inner).into();

        leaf.set_pos(size);
        self.inner.push(leaf).map_err(|_| Error::TreePushFailed)?;

        Ok(size)
    }

    /// Fetch, remove and return the last inserted leaf, if present.
    pub fn pop(&mut self) -> Result<Option<L>, Error> {
        self.inner.pop().map_err(|_| Error::TreePopFailed)
    }

    /// Fetch a leaf on a provided index.
    pub fn get(&self, n: u64) -> Result<Option<L>, Error> {
        self.inner
            .nth(n)
            .map(|o| o.map(|l| l.clone()))
            .map_err(|_| Error::TreePopFailed)
    }

    /// Return a full merkle opening for this poseidon tree for a given index.
    pub fn branch(
        &self,
        n: u64,
    ) -> Result<Option<PoseidonBranch<DEPTH>>, Error> {
        let branch = self.inner.nth(n).map_err(|_| Error::TreeBranchFailed)?;

        match branch {
            Some(b) => Ok(Some(PoseidonBranch::from(&b))),
            None => Ok(None),
        }
    }

    /// Return the current root/state of the tree.
    pub fn root(&self) -> Result<BlsScalar, Error> {
        self.branch(0)
            .map(|b| *b.unwrap_or_default().root())
            .or(Err(Error::TreeBranchFailed))
    }

    /// Provides an iterator over the leaves of the tree from a provided starting point.
    /// To iterate the entire tree, simply provide `0` as `start`.
    pub fn iter_walk(
        &self,
        start: u64,
    ) -> Result<impl IntoIterator<Item = Result<&L, CanonError>>, Error> {
        let result = self.inner.nth(start);
        match result {
            Ok(Some(iter)) => Ok(iter),
            _ => Err(Error::TreeIterFailed),
        }
    }

    /// Provides an iterator over the leaves of the tree which have been previously annotated via a custom `Walker` passed
    /// as argument.
    ///
    /// # Note
    /// This is only useful if annotate the tree is going to make the iteration perform sub-linearly.
    pub fn annotated_iter_walk<W>(
        &self,
        walker: W,
    ) -> Result<impl IntoIterator<Item = Result<&L, CanonError>>, Error>
    where
        W: Walker<NStack<L, A>, A>,
    {
        match Branch::walk(&self.inner, walker) {
            Ok(Some(iter)) => Ok(iter),
            _ => Err(Error::TreeIterFailed),
        }
    }
}
