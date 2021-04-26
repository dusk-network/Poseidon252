// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{PoseidonBranch, PoseidonLeaf, PoseidonTreeAnnotation};
use canonical::CanonError;
use canonical_derive::Canon;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Annotation, Cardinality, Combine, Nth};
use nstack::NStack;

/// Represents a Merkle Tree with a given depth that will be calculated using poseidon hash
///
/// The `BlsScalar` borrow of the annotation must represent the root poseidon merkle opening
/// for the annotated subtree
#[derive(Debug, Clone, Canon)]
pub struct PoseidonTree<L, A, const DEPTH: usize>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
    A: Annotation<L>,
{
    inner: NStack<L, A>,
}

impl<L, A, const DEPTH: usize> AsRef<NStack<L, A>> for PoseidonTree<L, A, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
    A: Annotation<L> + Combine<NStack<L, A>, A>,
{
    fn as_ref(&self) -> &NStack<L, A> {
        &self.inner
    }
}

impl<L, A, const DEPTH: usize> AsMut<NStack<L, A>> for PoseidonTree<L, A, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
    A: Annotation<L> + Combine<NStack<L, A>, A>,
{
    fn as_mut(&mut self) -> &mut NStack<L, A> {
        &mut self.inner
    }
}

impl<L, A, const DEPTH: usize> Default for PoseidonTree<L, A, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
    A: Annotation<L> + Combine<NStack<L, A>, A>,
{
    fn default() -> Self {
        PoseidonTree::new()
    }
}

impl<L, A, const DEPTH: usize> PoseidonTree<L, A, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
    A: Annotation<L> + Combine<NStack<L, A>, A>,
{
    /// Creates a new poseidon tree
    pub fn new() -> Self {
        let inner = NStack::new();

        Self { inner }
    }

    /// Append a leaf to the tree. Return the index of the appended leaf.
    ///
    /// Will call the `tree_pos_mut` implementation of the leaf to
    /// set its index
    pub fn push(&mut self, mut leaf: L) -> Result<u64, CanonError> {
        let size = Cardinality::combine(&self.inner).into();

        leaf.set_pos(size);
        self.inner.push(leaf)?;

        Ok(size)
    }

    /// Fetch, remove and return the last inserted leaf, if present.
    pub fn pop(&mut self) -> Result<Option<L>, CanonError> {
        self.inner.pop()
    }

    /// Fetch a leaf on a provided index.
    pub fn get(&self, n: u64) -> Result<Option<L>, CanonError> {
        self.inner.nth(n).map(|o| o.map(|l| l.clone()))
    }

    /// Return a full merkle opening for this poseidon tree for a given index.
    pub fn branch(
        &self,
        n: u64,
    ) -> Result<Option<PoseidonBranch<DEPTH>>, CanonError> {
        let branch = self.inner.nth(n)?;

        match branch {
            Some(b) => Ok(Some(PoseidonBranch::from(&b))),
            None => Ok(None),
        }
    }

    /// Return the current root/state of the tree.
    pub fn root(&self) -> Result<BlsScalar, CanonError> {
        self.branch(0).map(|b| b.unwrap_or_default().root().clone())
    }

    /// Provides an iterator over the leaves of the tree from a provided starting point.
    /// To iterate the entire tree, simply provide `0` as `start`.
    pub fn iter_walk(
        &self,
        start: u64,
    ) -> Result<impl IntoIterator<Item = Result<&L, CanonError>>, CanonError>
    {
        let result = self.inner.nth(start);
        match result {
            Ok(Some(iter)) => Ok(iter),
            _ => Err(CanonError::NotFound),
        }
    }
}
