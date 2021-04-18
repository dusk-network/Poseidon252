// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{
    PoseidonBranch, PoseidonLeaf, PoseidonTreeAnnotation,
    PoseidonWalkableAnnotation,
};
use crate::Error;
use canonical::{Canon, CanonError};
use canonical_derive::Canon;
use dusk_bls12_381::BlsScalar;
use microkelvin::{Annotation, Branch, Cardinality, Combine, Nth};
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
    pub fn push(&mut self, mut leaf: L) -> Result<usize, CanonError> {
        let size = match &self.inner {
            NStack::Leaf(l) => l.iter().filter(|l| l.is_some()).count(),
            NStack::Node(n) => n
                .iter()
                .filter_map(|n| n.as_ref())
                .map::<&Cardinality, _>(|n| n.annotation().borrow())
                .map::<u64, _>(|c| c.into())
                .map(|n| n as usize)
                .sum(),
        };

        leaf.set_pos(size as u64);
        self.inner.push(leaf)?;

        Ok(size)
    }

    /// Fetch, remove and return the last inserted leaf, if present.
    pub fn pop(&mut self) -> Result<Option<L>, CanonError> {
        self.inner.pop()
    }

    /// Fetch a leaf on a provided index.
    pub fn get(&self, n: usize) -> Result<Option<L>, CanonError> {
        self.inner.nth(n as u64).map(|o| o.map(|l| l.clone()))
    }

    /// Return a full merkle opening for this poseidon tree for a given index.
    pub fn branch(
        &self,
        n: usize,
    ) -> Result<Option<PoseidonBranch<DEPTH>>, CanonError> {
        let branch = self.inner.nth(n as u64)?;

        match branch {
            Some(b) => Ok(Some(PoseidonBranch::from(&b))),
            None => Ok(None),
        }
    }

    /// Return the current root/state of the tree.
    pub fn root(&self) -> Result<BlsScalar, CanonError> {
        self.branch(0).map(|b| b.unwrap_or_default().root().clone())
    }

    /// Iterates over the tree, provided its annotation implements [`PoseidonWalkableAnnotation`]
    pub fn iter_walk<D: Clone>(
        &self,
        data: D,
    ) -> Result<PoseidonTreeIterator<L, A, D, DEPTH>, &'static str>
    where
        A: PoseidonWalkableAnnotation<NStack<L, A>, D, L, A>,
        A: Annotation<L>,
    {
        PoseidonTreeIterator::new(&self, data)
    }
}

/// Main iterator of the poseidon tree.
///
/// Depends on an implementation of `PoseidonWalkableAnnotation` for the tree annotation
///
/// Every iteration will check for a valid `PoseidonWalkableAnnotation::poseidon_walk` call and
/// return a next leaf if the provided data holds true for the implemented logic
///
/// The data can be any struct that implements `Clone`, and will be used to define the traversal
/// path over the tree.
pub struct PoseidonTreeIterator<L, A, D, const DEPTH: usize>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
    D: Clone,
{
    tree: PoseidonTree<L, A, DEPTH>,
    pos: usize,
    data: D,
}

impl<L, A, D, const DEPTH: usize> PoseidonTreeIterator<L, A, D, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
    A: PoseidonWalkableAnnotation<NStack<L, A>, D, L, A>,
    A: Annotation<L>,
    D: Clone,
{
    /// Iterator constructor
    pub fn new(
        tree: &PoseidonTree<L, A, DEPTH>,
        data: D,
    ) -> Result<Self, &'static str> {
        let tree = tree.clone();

        // TODO - Naive implementation until iterable branch is implemented
        // https://github.com/dusk-network/microkelvin/issues/23
        let pos = <Branch<NStack<L, A>, A>>::walk(&tree.inner, |w| {
            A::poseidon_walk(w, data.clone())
        })
        .map_err(|_| "Error fetching the branch!")?
        .map(|l| l.pos())
        .unwrap_or(u64::max_value()) as usize;

        Ok(Self { tree, pos, data })
    }
}

impl<L, A, D, const DEPTH: usize> Iterator
    for PoseidonTreeIterator<L, A, D, DEPTH>
where
    L: PoseidonLeaf,
    A: PoseidonTreeAnnotation<L>,
    A: PoseidonWalkableAnnotation<NStack<L, A>, D, L, A>,
    A: Annotation<L> + Combine<NStack<L, A>, A>,
    D: Clone,
{
    type Item = Result<L, CanonError>;

    fn next(&mut self) -> Option<Self::Item> {
        let pos = self.pos;
        let (pos_p, overflow) = self.pos.overflowing_add(1);
        if overflow {
            return None;
        }
        self.pos = pos_p;

        match self.tree.get(pos) {
            // Hack until iterable branch is available
            // This will prevent the iteration over non-filtered data
            // https://github.com/dusk-network/microkelvin/issues/23
            Ok(Some(l)) if A::poseidon_leaf_found(&l, self.data.clone()) => {
                Some(Ok(l))
            }
            Ok(Some(_)) => self.next(),
            Err(e) => Some(Err(e)),
            _ => None,
        }
    }
}
