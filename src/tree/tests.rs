// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::tree::{
    PoseidonAnnotation, PoseidonLeaf, PoseidonMaxAnnotation, PoseidonTree,
};
use canonical::Canon;
use canonical_derive::Canon;
use canonical_host::MemStore;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use hades252::{ScalarStrategy, Strategy};

#[derive(
    Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon,
)]
pub struct MockLeaf {
    s: BlsScalar,
    pub pos: u64,
    pub expiration: u64,
}

impl From<u64> for MockLeaf {
    fn from(n: u64) -> MockLeaf {
        MockLeaf {
            s: BlsScalar::from(n),
            pos: 0,
            expiration: n / 3,
        }
    }
}

impl PoseidonLeaf<MemStore> for MockLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        self.s
    }

    fn pos(&self) -> u64 {
        self.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

impl Borrow<u64> for MockLeaf {
    fn borrow(&self) -> &u64 {
        &self.expiration
    }
}

#[test]
fn tree_append_fetch() {
    const MAX: usize = 4097;
    let mut v = [MockLeaf::default(); MAX];

    let mut tree: PoseidonTree<MockLeaf, PoseidonAnnotation, MemStore, 17> =
        PoseidonTree::new();
    for i in 0..MAX {
        let mut s = MockLeaf::from(i as u64);
        let pos = tree.push(s).unwrap();
        assert_eq!(i, pos);
        s.pos = i as u64;
        v[i] = s;
    }

    v.iter().enumerate().for_each(|(i, s)| {
        let l = tree.get(i).unwrap().unwrap();
        assert_eq!(s, &l);
    });

    v.iter().rev().for_each(|s| {
        let t = tree.pop().unwrap().unwrap();
        assert_eq!(s, &t);
    });
}

#[test]
fn tree_max_walk() {
    const MAX: usize = 1025;
    let mut v = [MockLeaf::default(); MAX];

    let mut tree: PoseidonTree<MockLeaf, PoseidonMaxAnnotation, MemStore, 17> =
        PoseidonTree::new();
    for i in 0..MAX {
        let mut s = MockLeaf::from(i as u64);
        let pos = tree.push(s).unwrap();
        assert_eq!(i, pos);
        s.pos = i as u64;
        v[i] = s;
    }

    let w = 170;
    let pos = w * 3;
    tree.iter_walk(w)
        .unwrap()
        .map(|l| l.unwrap())
        .enumerate()
        .for_each(|(i, leaf)| {
            assert_eq!(pos + i as u64, leaf.pos());
        });

    assert!(tree.iter_walk((MAX + 1) as u64).unwrap().next().is_none());
}

#[test]
fn tree_max_walk_non_continuous() {
    const MAX: usize = 1025;
    let mut v = [MockLeaf::default(); MAX];

    let mut tree: PoseidonTree<MockLeaf, PoseidonMaxAnnotation, MemStore, 17> =
        PoseidonTree::new();

    for i in 0..MAX {
        let mut s = MockLeaf::from(i as u64);

        if i % 4 == 0 {
            s.expiration = 0;
        }

        let pos = tree.push(s).unwrap();
        assert_eq!(i, pos);
        s.pos = i as u64;
        v[i] = s;
    }

    let w = 170;
    let mut pos = w * 3;
    tree.iter_walk(w)
        .unwrap()
        .map(|l| l.unwrap())
        .for_each(|leaf| {
            if pos % 4 == 0 {
                pos += 1;
            }
            assert_eq!(pos, leaf.pos());
            pos += 1;
        });

    assert!(tree.iter_walk((MAX + 1) as u64).unwrap().next().is_none());
}

#[test]
fn tree_branch_leaf() {
    const DEPTH: usize = 17;

    let mut h = ScalarStrategy::new();
    let zero = [BlsScalar::zero(); hades252::WIDTH];
    let mut perm = zero;

    [
        1, 2, 3, 4, 5, 8, 16, 32, 64, 128, 256, 512, 1023, 1024, 1025,
    ]
    .iter()
    .for_each(|w| {
        let w = *w;

        let mut tree: PoseidonTree<
            MockLeaf,
            PoseidonAnnotation,
            MemStore,
            DEPTH,
        > = PoseidonTree::new();

        for i in 0..w {
            let l = MockLeaf::from(i as u64);
            tree.push(l).unwrap();
        }

        for i in 0..w {
            let root = tree.root().unwrap();
            let branch = tree.branch(i).unwrap().unwrap();
            let leaf = *branch;

            assert_eq!(BlsScalar::from(i as u64), leaf);

            let root_p = branch.as_ref().iter().take(DEPTH - 1).fold(
                leaf,
                |needle, level| {
                    assert_eq!(needle, **level);

                    perm.copy_from_slice(level.as_ref());
                    h.perm(&mut perm);

                    perm[1]
                },
            );

            assert_eq!(root, root_p);
        }
    });
}

#[test]
fn tree_branch_depth() {
    let mut h = ScalarStrategy::new();
    let mut tree: PoseidonTree<MockLeaf, PoseidonAnnotation, MemStore, 17> =
        PoseidonTree::new();

    let leaf = MockLeaf::from(1);
    tree.push(leaf).unwrap();

    let mut perm_base = [BlsScalar::zero(); hades252::WIDTH];
    perm_base[0] = BlsScalar::one();
    perm_base[1] = leaf.poseidon_hash();

    let mut perm = perm_base;
    for _ in 0..17 {
        let needle = perm[1];
        perm.copy_from_slice(&perm_base);
        perm[1] = needle;
        h.perm(&mut perm);
    }

    let branch = tree.branch(0).unwrap().unwrap();
    assert_eq!(perm[1], branch.root());
}
