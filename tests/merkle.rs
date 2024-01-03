// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]
#![cfg(feature = "merkle")]

use dusk_plonk::prelude::Error as PlonkError;
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

const A: usize = 4;
const MERKLE_CAPACITY: usize = 12;

#[derive(Debug, Default)]
pub struct MerkleCircuit {
    input: [BlsScalar; A],
    output: BlsScalar,
}

impl MerkleCircuit {
    pub fn new(input: [BlsScalar; A], output: BlsScalar) -> Self {
        Self { input, output }
    }
}

impl Circuit for MerkleCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        let mut input_witnesses = [Composer::ZERO; A];
        for (i, witness) in input_witnesses.iter_mut().enumerate() {
            *witness = composer.append_witness(self.input[i]);
        }

        let calculated = sponge::merkle::gadget(composer, &input_witnesses);
        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(calculated)
            .public(self.output);
        composer.append_gate(constraint);

        Ok(())
    }
}

#[test]
fn merkle_sponge() -> Result<(), PlonkError> {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let label = b"merkle-sponge-tester";
    let pp = PublicParameters::setup(1 << MERKLE_CAPACITY, &mut rng)?;
    let (prover, verifier) = Compiler::compile::<MerkleCircuit>(&pp, label)
        .expect("Circuit should compile");

    let mut input = [BlsScalar::zero(); A];
    for scalar in input.iter_mut() {
        *scalar = BlsScalar::random(&mut rng);
    }
    let expected_output = sponge::merkle::hash(&input);

    let circuit = MerkleCircuit::new(input, expected_output);

    let (proof, _) = prover.prove(&mut rng, &circuit)?;

    let public_inputs = [expected_output];
    verifier.verify(&proof, &public_inputs)?;

    Ok(())
}
