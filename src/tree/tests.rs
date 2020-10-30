// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::tree::zk::merkle_opening;
use crate::tree::{PoseidonAnnotation, PoseidonTree};
use anyhow::Result;
use canonical::Canon;
use canonical_derive::Canon;
use canonical_host::MemStore;
use dusk_plonk::prelude::*;
use hades252::{ScalarStrategy, Strategy};

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon)]
struct MockLeaf(pub BlsScalar);

impl From<u64> for MockLeaf {
    fn from(n: u64) -> MockLeaf {
        MockLeaf(BlsScalar::from(n))
    }
}

impl Into<BlsScalar> for &MockLeaf {
    fn into(self) -> BlsScalar {
        self.0
    }
}

#[test]
fn tree_append_fetch() {
    let mut tree: PoseidonTree<MockLeaf, PoseidonAnnotation, MemStore, 17> =
        PoseidonTree::new();
    let mut v = vec![];
    let max = 4097;

    for i in 0..max {
        let s = MockLeaf::from(i as u64);
        let pos = tree.push(s).unwrap();
        assert_eq!(i, pos);
        v.push(s);
    }

    v.iter().enumerate().for_each(|(i, s)| {
        let l = tree.get(i).unwrap().unwrap();
        assert_eq!(s, &l);
    });

    v.into_iter().rev().for_each(|s| {
        let t = tree.pop().unwrap().unwrap();
        assert_eq!(s, t);
    });
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
fn tree_merkle_opening() -> Result<()> {
    const DEPTH: usize = 17;

    let pub_params = PublicParameters::setup(1 << 15, &mut rand::thread_rng())?;
    let (ck, ok) = pub_params.trim(1 << 15)?;

    let mut tree: PoseidonTree<MockLeaf, PoseidonAnnotation, MemStore, DEPTH> =
        PoseidonTree::new();

    for i in 0..1024 {
        let l = MockLeaf::from(i as u64);
        tree.push(l)?;
    }

    let gadget_tester =
        |composer: &mut StandardComposer,
         tree: &PoseidonTree<MockLeaf, PoseidonAnnotation, MemStore, DEPTH>,
         n: usize| {
            let branch = tree.branch(n).unwrap().unwrap();
            let root = tree.root().unwrap();

            let leaf = BlsScalar::from(n as u64);
            let leaf = composer.add_input(leaf);

            let root_p = merkle_opening::<DEPTH>(composer, &branch, leaf);
            composer.constrain_to_constant(root_p, BlsScalar::zero(), -root);
        };

    let label = b"opening_gadget";

    for i in [0, 567, 1023].iter() {
        let mut prover = Prover::new(label);
        gadget_tester(prover.mut_cs(), &tree, *i);
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        let mut verifier = Verifier::new(label);
        gadget_tester(verifier.mut_cs(), &tree, *i);
        verifier.preprocess(&ck)?;
        let pi = verifier.mut_cs().public_inputs.clone();
        verifier.verify(&proof, &ok, &pi).unwrap();
    }

    Ok(())
}
