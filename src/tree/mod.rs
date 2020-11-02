// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use anyhow::{anyhow, Result};
use canonical::{Canon, Store};
use core::marker::PhantomData;
use dusk_plonk::prelude::BlsScalar;
use microkelvin::{Branch, Cardinality, Nth};
use nstack::NStack;

pub use annotation::{
    PoseidonAnnotation, PoseidonMaxAnnotation, PoseidonTreeAnnotation,
    PoseidonWalkableAnnotation,
};
pub use branch::{PoseidonBranch, PoseidonLevel};

mod annotation;
mod branch;

/// Zero-Knowledge implementations for the poseidon tree
pub mod zk;

#[cfg(test)]
mod tests;

/// A struct that will be used as a poseidon tree leaf must implement this trait
pub trait PoseidonLeaf<S>: Canon<S> + Clone
where
    S: Store,
{
    fn poseidon_hash(&self) -> BlsScalar;
}

/// Represents a Merkle Tree with a given depth that will be calculated using poseidon hash
///
/// The `BlsScalar` borrow of the annotation must represent the root poseidon merkle opening
/// for the annotated subtree
#[derive(Debug, Clone)]
pub struct PoseidonTree<L, A, S, const DEPTH: usize>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
{
    inner: NStack<L, A, S>,
}

impl<L, A, S, const DEPTH: usize> AsRef<NStack<L, A, S>>
    for PoseidonTree<L, A, S, DEPTH>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
{
    fn as_ref(&self) -> &NStack<L, A, S> {
        &self.inner
    }
}

impl<L, A, S, const DEPTH: usize> AsMut<NStack<L, A, S>>
    for PoseidonTree<L, A, S, DEPTH>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
{
    fn as_mut(&mut self) -> &mut NStack<L, A, S> {
        &mut self.inner
    }
}

impl<L, A, S, const DEPTH: usize> PoseidonTree<L, A, S, DEPTH>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
{
    /// Creates a new poseidon tree
    pub fn new() -> Self {
        let inner = NStack::new();

        Self { inner }
    }

    /// Append a leaf to the tree. Return the index of the appended leaf.
    pub fn push(&mut self, leaf: L) -> Result<usize> {
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

        self.inner
            .push(leaf)
            .map_err(|e| anyhow!("Error pushing to the tree: {:?}", e))?;

        Ok(size)
    }

    /// Fetch, remove and return the last inserted leaf, if present.
    pub fn pop(&mut self) -> Result<Option<L>> {
        self.inner
            .pop()
            .map_err(|e| anyhow!("Error pop from the tree: {:?}", e))
    }

    /// Fetch a leaf on a provided index.
    pub fn get(&self, n: usize) -> Result<Option<L>> {
        self.inner
            .nth::<DEPTH>(n as u64)
            .map(|o| o.map(|l| l.clone()))
            .map_err(|e| {
                anyhow!("Error fetching the Nth item from the tree: {:?}", e)
            })
    }

    /// Return a full merkle opening for this poseidon tree for a given index.
    pub fn branch(&self, n: usize) -> Result<Option<PoseidonBranch<DEPTH>>> {
        let branch = self.inner.nth::<DEPTH>(n as u64).map_err(|e| {
            anyhow!("Error fetching the Nth item from the tree: {:?}", e)
        })?;

        match branch {
            Some(b) => Ok(Some(PoseidonBranch::from(&b))),
            None => Ok(None),
        }
    }

    /// Return the current root/state of the tree.
    pub fn root(&self) -> Result<BlsScalar> {
        self.branch(0).map(|b| b.unwrap_or_default().root())
    }

    pub fn iter_walk<D: Clone>(
        &self,
        data: D,
    ) -> Result<PoseidonTreeIterator<'_, L, A, S, A, D, DEPTH>>
    where
        A: PoseidonWalkableAnnotation<NStack<L, A, S>, D, L, S>,
    {
        PoseidonTreeIterator::new(&self.inner, data)
    }
}

pub struct PoseidonTreeIterator<'a, L, A, S, W, D, const DEPTH: usize>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
    W: PoseidonWalkableAnnotation<NStack<L, A, S>, D, L, S>,
    D: Clone,
{
    tree: &'a NStack<L, A, S>,
    data: D,
    walk: PhantomData<W>,
    branch: Option<Branch<'a, NStack<L, A, S>, S, DEPTH>>,
}

impl<'a, L, A, S, W, D, const DEPTH: usize>
    PoseidonTreeIterator<'a, L, A, S, W, D, DEPTH>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
    W: PoseidonWalkableAnnotation<NStack<L, A, S>, D, L, S>,
    D: Clone,
{
    pub fn new(tree: &'a NStack<L, A, S>, data: D) -> Result<Self> {
        let branch = <Branch<NStack<L, A, S>, S, DEPTH>>::walk(tree, |w| {
            W::poseidon_walk(w, data.clone())
        })
        .map_err(|e| anyhow!("Error fetching the branch: {:?}", e))?;

        Ok(Self {
            tree,
            data,
            walk: PhantomData,
            branch,
        })
    }
}

impl<'a, L, A, S, W, D, const DEPTH: usize> Iterator
    for PoseidonTreeIterator<'a, L, A, S, W, D, DEPTH>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
    W: PoseidonWalkableAnnotation<NStack<L, A, S>, D, L, S>,
    D: Clone,
{
    type Item = Result<L>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = match &self.branch {
            Some(b) => (*b).clone(),
            None => return None,
        };

        // We are only iterating over the same base compound, so we have an infinite loop here
        // Check issue #86
        // https://github.com/dusk-network/dusk-blindbid/issues/86#issuecomment-720664968
        self.branch = match Branch::walk(self.tree, |w| {
            W::poseidon_walk(w, self.data.clone())
        })
        .map_err(|e| anyhow!("Error fetching the branch: {:?}", e))
        {
            Ok(b) => b,
            Err(e) => return Some(Err(e)),
        };

        Some(Ok(next))
    }
}
