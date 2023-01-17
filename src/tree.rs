// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Implementation of a Merkle Tree with a Dusk-Poseidon backend and
//! zero-knowledge opening proof powered by PLONK.

mod annotation;
mod branch;
mod leaf;
mod zk;

pub use annotation::PoseidonAnnotation;

#[cfg(feature = "rkyv-impl")]
pub use branch::{
    ArchivedPoseidonBranch, ArchivedPoseidonLevel, PoseidonBranchResolver,
    PoseidonLevelResolver,
};
pub use branch::{PoseidonBranch, PoseidonLevel};

pub use leaf::PoseidonLeaf;
pub use zk::merkle_opening;

use core::borrow::Borrow;

use dusk_bls12_381::BlsScalar;
use microkelvin::{Branch, Walker};
use nstack::annotation::{Cardinality, Keyed};
use nstack::NStack;
use ranno::Annotation;

/// Represents a Merkle Tree with a given depth that will be calculated using
/// the Poseidon Hash technique.
#[derive(Debug, Default)]
pub struct PoseidonTree<L, K, const DEPTH: usize> {
    inner: NStack<L, PoseidonAnnotation<K>>,
}

impl<L, K, const DEPTH: usize> Clone for PoseidonTree<L, K, DEPTH>
where
    L: Clone + PoseidonLeaf + Keyed<K>,
    K: Clone + PartialOrd,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<L, K, const DEPTH: usize> AsRef<NStack<L, PoseidonAnnotation<K>>>
    for PoseidonTree<L, K, DEPTH>
{
    fn as_ref(&self) -> &NStack<L, PoseidonAnnotation<K>> {
        &self.inner
    }
}

impl<L, K, const DEPTH: usize> AsMut<NStack<L, PoseidonAnnotation<K>>>
    for PoseidonTree<L, K, DEPTH>
{
    fn as_mut(&mut self) -> &mut NStack<L, PoseidonAnnotation<K>> {
        &mut self.inner
    }
}

impl<L, K, const DEPTH: usize> PoseidonTree<L, K, DEPTH> {
    /// Creates a new poseidon tree
    pub const fn new() -> Self {
        Self {
            inner: NStack::new(),
        }
    }
}

impl<L, K, const DEPTH: usize> PoseidonTree<L, K, DEPTH>
where
    L: PoseidonLeaf + Keyed<K>,
    K: Clone + PartialOrd,
{
    /// Append a leaf to the tree. Return the index of the appended leaf.
    pub fn push(&mut self, mut leaf: L) -> u64 {
        let anno = PoseidonAnnotation::from_child(&self.inner);
        let cardinality: &Cardinality = anno.borrow();

        let pos = **cardinality;

        leaf.set_pos(pos);
        self.inner.push(leaf);

        pos
    }

    /// Fetch, remove and return the last inserted leaf, if present.
    pub fn pop(&mut self) -> Option<L> {
        self.inner.pop()
    }

    /// Fetch a leaf on a provided index.
    pub fn get(&self, n: u64) -> Option<L>
    where
        L: Clone,
    {
        self.inner.nth(n).map(|b| (*b).clone())
    }

    /// Return a full merkle opening for this poseidon tree for a given index.
    pub fn branch(&self, n: u64) -> Option<PoseidonBranch<DEPTH>> {
        self.inner.nth(n).as_ref().map(PoseidonBranch::from)
    }

    /// Return the current root/state of the tree.
    pub fn root(&self) -> BlsScalar {
        self.branch(0).map(|b| *b.root()).unwrap_or_default()
    }

    /// Provides an iterator over the leaves of the tree from a provided
    /// starting point. To iterate the entire tree, simply provide `0` as
    /// `start`.
    pub fn iter_walk(
        &self,
        start: u64,
    ) -> Option<impl IntoIterator<Item = &L>> {
        self.inner.nth(start)
    }

    /// Provides an iterator over the leaves of the tree which have been
    /// previously annotated via a custom `Walker` passed as argument.
    ///
    /// # Note
    /// This is only useful if annotate the tree is going to make the iteration
    /// perform sub-linearly.
    pub fn annotated_iter_walk<W>(
        &self,
        walker: W,
    ) -> Option<impl IntoIterator<Item = &L>>
    where
        W: Walker<NStack<L, PoseidonAnnotation<K>>, PoseidonAnnotation<K>>,
    {
        Branch::walk(&self.inner, walker)
    }
}
