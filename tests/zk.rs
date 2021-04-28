// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.
#![cfg(feature = "canon")]

mod max_annotation;
use dusk_plonk::circuit;
use dusk_plonk::error::Error as PlonkError;
use dusk_plonk::prelude::*;
use dusk_poseidon::tree::{
    self, PoseidonAnnotation, PoseidonBranch, PoseidonTree,
};
use max_annotation::MockLeaf;
use rand_core::{CryptoRng, OsRng, RngCore};

const DEPTH: usize = 17;
const CAPACITY: usize = 1 << 15;
type Tree = PoseidonTree<MockLeaf, PoseidonAnnotation, DEPTH>;

struct MerkleOpeningCircuit {
    branch: PoseidonBranch<DEPTH>,
}

impl MerkleOpeningCircuit {
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        tree: &mut Tree,
    ) -> Self {
        let leaf = MockLeaf::random(rng);
        let pos = tree
            .push(leaf.clone())
            .expect("Failed to append to the tree");

        let branch = tree
            .branch(pos)
            .expect("Failed to read the tree for the branch")
            .expect(
                "Failed to fetch the branch of the created leaf from the tree",
            );

        Self { branch }
    }

    pub fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![(*self.branch.root()).into()]
    }
}

impl Circuit for MerkleOpeningCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut StandardComposer,
    ) -> Result<(), PlonkError> {
        let root = self.branch.root();
        let root_p = tree::merkle_opening::<DEPTH>(composer, &self.branch);

        composer.constrain_to_constant(root_p, BlsScalar::zero(), Some(-root));

        Ok(())
    }

    fn padded_circuit_size(&self) -> usize {
        CAPACITY
    }
}

#[test]
fn tree_merkle_opening() {
    let mut rng = OsRng;
    let pp = PublicParameters::setup(CAPACITY, &mut rng).unwrap();
    let label = b"dusk-network";

    let mut tree = Tree::default();
    let mut circuit = MerkleOpeningCircuit::random(&mut rng, &mut tree);
    let (pk, vd) = circuit.compile(&pp).expect("Failed to compile circuit");

    let mut tree = Tree::default();
    for _ in 0..13 {
        let mut circuit = MerkleOpeningCircuit::random(&mut rng, &mut tree);

        let proof = circuit
            .gen_proof(&pp, &pk, label)
            .expect("Failed to generate proof");
        let pi = circuit.public_inputs();

        circuit::verify_proof(
            &pp,
            vd.key(),
            &proof,
            pi.as_slice(),
            vd.pi_pos(),
            label,
        )
        .expect("Proof verification failed");
    }
}
