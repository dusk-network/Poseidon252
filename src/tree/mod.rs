// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "canon_host")]
use anyhow::anyhow;
use anyhow::Result;
use canonical::{Canon, Store};
use canonical_derive::Canon;
use dusk_plonk::prelude::BlsScalar;
use microkelvin::{Annotated, Child, ChildMut, Compound};
#[cfg(feature = "canon_host")]
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
#[cfg(feature = "canon_host")]
mod tests;

/// A struct that will be used as a poseidon tree leaf must implement this trait
///
/// After [`PoseidonTree::push`], `tree_pos_mut` will be called to set the
/// index of the leaf on the tree
pub trait PoseidonLeaf<S>: Canon<S> + Clone
where
    S: Store,
{
    /// Poseidon hash implementation of the leaf structure.
    ///
    /// The result of this function will be used as opening for the merkle tree.
    fn poseidon_hash(&self) -> BlsScalar;

    /// Index of the leaf structure on the merkle tree.
    fn pos(&self) -> u64;

    /// Index of the leaf structure on the merkle tree.
    ///
    /// This method is internally used to set the index after the data has been inserted in the
    /// merkle tree.
    fn set_pos(&mut self, pos: u64);
}

/// Represents a Merkle Tree with a given depth that will be calculated using poseidon hash
///
/// The `BlsScalar` borrow of the annotation must represent the root poseidon merkle opening
/// for the annotated subtree
#[derive(Debug, Clone, Canon)]
pub struct PoseidonTree<L, A, S, const DEPTH: usize>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
{
    inner: NStack<L, A, S>,
}

impl<L, A, S, const DEPTH: usize> Compound<S> for PoseidonTree<L, A, S, DEPTH>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
{
    type Leaf = L;
    type Annotation = A;

    fn child(&self, ofs: usize) -> Child<Self, S> {
        match self.inner.child(ofs) {
            Child::Leaf(l) => Child::Leaf(l),
            // Unsafe pointer conversion due to the inability to convert between annotated
            // representations
            //
            // Check https://github.com/dusk-network/microkelvin/issues/24
            Child::Node(n) => Child::Node(unsafe {
                &*(n as *const Annotated<NStack<L, A, S>, S>
                    as *const Annotated<PoseidonTree<L, A, S, DEPTH>, S>)
            }),
            Child::EndOfNode => Child::EndOfNode,
        }
    }

    fn child_mut(&mut self, ofs: usize) -> ChildMut<Self, S> {
        match self.inner.child_mut(ofs) {
            ChildMut::Leaf(l) => ChildMut::Leaf(l),
            // Unsafe pointer conversion due to the inability to convert between annotated
            // representations
            //
            // Check https://github.com/dusk-network/microkelvin/issues/24
            ChildMut::Node(n) => ChildMut::Node(unsafe {
                &mut *(n as *mut Annotated<NStack<L, A, S>, S>
                    as *mut Annotated<PoseidonTree<L, A, S, DEPTH>, S>)
            }),
            ChildMut::EndOfNode => ChildMut::EndOfNode,
        }
    }
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
    ///
    /// Will call the `tree_pos_mut` implementation of the leaf to
    /// set its index
    #[cfg(feature = "canon_host")]
    pub fn push(&mut self, mut leaf: L) -> Result<usize> {
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
        self.inner
            .push(leaf)
            .map_err(|e| anyhow!("Error pushing to the tree: {:?}", e))?;

        Ok(size)
    }

    /// Fetch, remove and return the last inserted leaf, if present.
    #[cfg(feature = "canon_host")]
    pub fn pop(&mut self) -> Result<Option<L>> {
        self.inner
            .pop()
            .map_err(|e| anyhow!("Error pop from the tree: {:?}", e))
    }

    /// Fetch a leaf on a provided index.
    #[cfg(feature = "canon_host")]
    pub fn get(&self, n: usize) -> Result<Option<L>> {
        self.inner
            .nth::<DEPTH>(n as u64)
            .map(|o| o.map(|l| l.clone()))
            .map_err(|e| {
                anyhow!("Error fetching the Nth item from the tree: {:?}", e)
            })
    }

    /// Return a full merkle opening for this poseidon tree for a given index.
    #[cfg(feature = "canon_host")]
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
    #[cfg(feature = "canon_host")]
    pub fn root(&self) -> Result<BlsScalar> {
        self.branch(0).map(|b| b.unwrap_or_default().root())
    }

    /// Iterates over the tree, provided its annotation implements [`PoseidonWalkableAnnotation`]
    #[cfg(feature = "canon_host")]
    pub fn iter_walk<D: Clone>(
        &self,
        data: D,
    ) -> Result<PoseidonTreeIterator<L, A, S, D, DEPTH>>
    where
        A: PoseidonWalkableAnnotation<NStack<L, A, S>, D, L, S>,
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
#[cfg(feature = "canon_host")]
pub struct PoseidonTreeIterator<L, A, S, D, const DEPTH: usize>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    S: Store,
    D: Clone,
{
    tree: PoseidonTree<L, A, S, DEPTH>,
    pos: usize,
    data: D,
}

#[cfg(feature = "canon_host")]
impl<L, A, S, D, const DEPTH: usize> PoseidonTreeIterator<L, A, S, D, DEPTH>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    A: PoseidonWalkableAnnotation<NStack<L, A, S>, D, L, S>,
    S: Store,
    D: Clone,
{
    /// Iterator constructor
    pub fn new(tree: &PoseidonTree<L, A, S, DEPTH>, data: D) -> Result<Self> {
        let tree = tree.clone();

        // TODO - Naive implementation until iterable branch is implemented
        // https://github.com/dusk-network/microkelvin/issues/23
        let pos = <Branch<NStack<L, A, S>, S, DEPTH>>::walk(&tree.inner, |w| {
            A::poseidon_walk(w, data.clone())
        })
        .map_err(|e| anyhow!("Error fetching the branch: {:?}", e))?
        .map(|l| l.pos())
        .unwrap_or(u64::max_value()) as usize;

        Ok(Self { tree, pos, data })
    }
}

#[cfg(feature = "canon_host")]
impl<L, A, S, D, const DEPTH: usize> Iterator
    for PoseidonTreeIterator<L, A, S, D, DEPTH>
where
    L: PoseidonLeaf<S>,
    A: PoseidonTreeAnnotation<L, S>,
    A: PoseidonWalkableAnnotation<NStack<L, A, S>, D, L, S>,
    S: Store,
    D: Clone,
{
    type Item = Result<L>;

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
