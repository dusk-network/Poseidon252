// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

mod max_annotation;

use dusk_plonk::error::Error as PlonkError;
use dusk_poseidon::tree::{self, PoseidonBranch, PoseidonTree};
use max_annotation::MockLeaf;
use rand::rngs::{OsRng, StdRng};
use rand::{CryptoRng, RngCore, SeedableRng};

use dusk_plonk::prelude::*;

const DEPTH: usize = 17;
const CAPACITY: usize = 15;

type Tree = PoseidonTree<MockLeaf, u64, DEPTH>;

#[derive(Default)]
struct MerkleOpeningCircuit {
    branch: PoseidonBranch<DEPTH>,
}

impl MerkleOpeningCircuit {
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        tree: &mut Tree,
    ) -> Self {
        let leaf = MockLeaf::random(rng);
        let pos = tree.push(leaf);

        let branch = tree.branch(pos).expect(
            "Failed to fetch the branch of the created leaf from the tree",
        );

        Self { branch }
    }
}

impl Circuit for MerkleOpeningCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), PlonkError>
    where
        C: Composer,
    {
        use std::ops::Deref;

        let leaf: BlsScalar = *self.branch.deref();
        let leaf = composer.append_witness(leaf);

        let root = self.branch.root();
        let root = composer.append_witness(*root);

        let root_p =
            tree::merkle_opening::<C, DEPTH>(composer, &self.branch, leaf);

        composer.assert_equal(root_p, root);

        Ok(())
    }
}

#[test]
fn tree_merkle_opening() {
    let label = b"dusk-network";
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    let mut rng = StdRng::seed_from_u64(0xbeef);

    let (prover, verifier) =
        Compiler::compile::<MerkleOpeningCircuit>(&pp, label)
            .expect("Circuit should compile successfully");

    let mut tree = Tree::default();
    let circuit = MerkleOpeningCircuit::random(&mut rng, &mut tree);

    let (proof, public_inputs) = prover
        .prove(&mut rng, &circuit)
        .expect("Proving the circuit should succeed");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Proof verification should succeed");
}
