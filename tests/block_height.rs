// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use dusk_poseidon::tree::{PoseidonLeaf, PoseidonTree};
use microkelvin::{Child, Compound, Step, Walk, Walker};
use nstack::annotation::{Keyed, MaxKey};
use ranno::Annotation;

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
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

    fn pos(&self) -> &u64 {
        &self.pos
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

#[derive(Copy, Clone, Default, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct BlockHeight(pub(crate) u64);

// Walker method to find the elements that are above a certain a block height.
pub struct BlockHeightFilter(u64);

impl<C, A> Walker<C, A> for BlockHeightFilter
where
    C: Compound<A>,
    C::Leaf: Keyed<BlockHeight>,
    A: Annotation<C> + Borrow<MaxKey<BlockHeight>>,
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
                    let anno = n.anno();

                    let max_node_block_height: BlockHeight =
                        match *(*anno).borrow() {
                            MaxKey::NegativeInfinity => return Step::Abort,
                            MaxKey::Maximum(value) => value,
                        };
                    if max_node_block_height.0 >= self.0 {
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

#[test]
fn custom_walker_iter() {
    let mut tree = PoseidonTree::<TestLeaf, BlockHeight, 17>::new();

    // Fill the tree with different leafs with different block heights.
    for i in 0..18 {
        let leaf = TestLeaf::new(i);
        let pos = tree.push(leaf);
        assert_eq!(pos, i);
        let key: BlockHeight = *leaf.key();
        assert_eq!(key, BlockHeight(i as u64));
    }

    let mut leaf_count = 0;
    // For a block_height of 0, the custom walker should iterate over all the
    // leaves.

    tree.annotated_iter_walk(BlockHeightFilter(0))
        .expect("there should be an annotate iterator returned")
        .into_iter()
        .enumerate()
        .for_each(|(idx, l)| {
            leaf_count += 1;
            let leaf_height: BlockHeight = *l.key();
            // Check that the heights are the expected ones
            assert_eq!(leaf_height, BlockHeight(idx as u64));
        });

    assert_eq!(leaf_count, 18);

    // For a block_height of 20, we should fail to get an iterator over the tree
    // as no leaf satisfies the criteria.
    assert!(tree.annotated_iter_walk(BlockHeightFilter(20)).is_none());

    leaf_count = 0;
    // For a block_height of 15, the custom walker should iterate over the last
    // two subtrees which means from leaves [12, 13, 14, 15] & [16, 17, _,
    // _].
    tree.annotated_iter_walk(BlockHeightFilter(15))
        .expect("there should be an annotate iterator returned")
        .into_iter()
        .enumerate()
        .for_each(|(idx, l)| {
            leaf_count += 1;
            // Check that the heights are the expected ones
            let leaf_height: BlockHeight = *l.key();
            assert_eq!(leaf_height, BlockHeight(idx as u64 + 12));
        });
    assert_eq!(leaf_count, 6);
}
