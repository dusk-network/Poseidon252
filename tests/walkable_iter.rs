// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "canon")]
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use dusk_poseidon::tree::{
    PoseidonAnnotation, PoseidonLeaf, PoseidonTree, PoseidonTreeAnnotation,
};
use microkelvin::{
    Annotation, Cardinality, Child, Combine, Compound, Keyed, MaxKey, Step,
    Walk, Walker,
};

#[derive(
    Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon,
)]
pub struct TestLeaf {
    hash: BlsScalar,
    pos: u64,
    height: BlockHeight,
}

impl TestLeaf {
    fn new(height: u64) -> TestLeaf {
        TestLeaf {
            hash: BlsScalar::zero(),
            pos: 0,
            height: BlockHeight(height),
        }
    }
}

impl Keyed<BlockHeight> for TestLeaf {
    fn key(&self) -> &BlockHeight {
        &self.height
    }
}

impl PoseidonLeaf for TestLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        self.hash
    }

    fn pos(&self) -> u64 {
        self.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

impl Borrow<u64> for TestLeaf {
    fn borrow(&self) -> &u64 {
        &self.pos
    }
}

#[derive(
    Copy, Clone, Default, Debug, Canon, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct BlockHeight(pub(crate) u64);

#[derive(Clone, Debug, Default, Canon)]
pub struct TestAnnotation {
    ann: PoseidonAnnotation,
    block_height: MaxKey<BlockHeight>,
}

impl Borrow<MaxKey<BlockHeight>> for TestAnnotation {
    fn borrow(&self) -> &MaxKey<BlockHeight> {
        &self.block_height
    }
}

impl Borrow<Cardinality> for TestAnnotation {
    fn borrow(&self) -> &Cardinality {
        self.ann.borrow()
    }
}

impl Borrow<BlsScalar> for TestAnnotation {
    fn borrow(&self) -> &BlsScalar {
        self.ann.borrow()
    }
}

impl<L> Annotation<L> for TestAnnotation
where
    L: PoseidonLeaf,
    L: Borrow<u64>,
    L: Keyed<BlockHeight>,
{
    fn from_leaf(leaf: &L) -> Self {
        let ann = PoseidonAnnotation::from_leaf(leaf);
        let block_height = MaxKey::from_leaf(leaf);

        Self { ann, block_height }
    }
}

impl<C, A> Combine<C, A> for TestAnnotation
where
    C: Compound<A>,
    C::Leaf: PoseidonLeaf + Keyed<BlockHeight> + Borrow<u64>,
    A: Annotation<C::Leaf>
        + PoseidonTreeAnnotation<C::Leaf>
        + Borrow<Cardinality>
        + Borrow<MaxKey<BlockHeight>>,
{
    fn combine(node: &C) -> Self {
        TestAnnotation {
            ann: PoseidonAnnotation::combine(node),
            block_height: MaxKey::combine(node),
        }
    }
}

// Walker method to find the elements that are avobe a certain a block height.
pub struct BlockHeightFilter(u64);

impl<C, A> Walker<C, A> for BlockHeightFilter
where
    C: Compound<A>,
    C::Leaf: Keyed<BlockHeight>,
    A: Combine<C, A> + Borrow<MaxKey<BlockHeight>>,
{
    fn walk(&mut self, walk: Walk<C, A>) -> Step {
        for i in 0.. {
            match walk.child(i) {
                Child::Leaf(l) => {
                    if l.key().0 >= self.0 {
                        return Step::Found(i);
                    } else {
                        self.0 -= 1
                    }
                }
                Child::Node(n) => {
                    let max_node_block_height: u64 =
                        match n.annotation().borrow() {
                            MaxKey::NegativeInfinity => return Step::Abort,
                            MaxKey::Maximum(value) => value.0,
                        };
                    if max_node_block_height >= self.0 {
                        return Step::Into(i);
                    } else {
                        self.0 -= 1
                    }
                }
                Child::Empty => (),
                Child::EndOfNode => return Step::Advance,
            }
        }
        unreachable!()
    }
}

mod tests {
    use super::*;
    use dusk_poseidon::Error;

    #[test]
    fn custom_walker_iter() -> Result<(), Error> {
        let mut tree = PoseidonTree::<TestLeaf, TestAnnotation, 17>::new();

        // Fill the tree with different leafs with different block heights.
        for i in 0..18 {
            let leaf = TestLeaf::new(i);
            let pos = tree.push(leaf)?;
            assert_eq!(pos, i);
            let key: BlockHeight = *leaf.key();
            assert_eq!(key, BlockHeight(i as u64));
        }

        let mut leaf_count = 0;
        // For a block_height of 0, the custom walker should iterate over all the leaves.
        tree.annotated_iter_walk(BlockHeightFilter(0))?
            .into_iter()
            .enumerate()
            .for_each(|(idx, l)| {
                if l.is_ok() {
                    leaf_count += 1
                }
                // Check that the heights are the expected ones
                let leaf_height: BlockHeight = *l.unwrap().key();
                assert_eq!(leaf_height, BlockHeight(idx as u64));
            });
        assert_eq!(leaf_count, 18);

        // For a block_height of 20, we should fail to get an iterator over the tree as no leaf
        // satisfies the criteria.
        assert!(tree.annotated_iter_walk(BlockHeightFilter(20)).is_err());

        leaf_count = 0;
        // For a block_height of 15, the custom walker should iterate over the last two subtrees which means from
        // leaves [12, 13, 14, 15] & [16, 17, _, _].
        tree.annotated_iter_walk(BlockHeightFilter(15))?
            .into_iter()
            .enumerate()
            .for_each(|(idx, l)| {
                if l.is_ok() {
                    leaf_count += 1;
                    // Check that the heights are the expected ones
                    let leaf_height: BlockHeight = *l.unwrap().key();
                    assert_eq!(leaf_height, BlockHeight(idx as u64 + 12));
                }
            });
        assert_eq!(leaf_count, 6);
        Ok(())
    }
}
