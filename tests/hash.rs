// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "zk")]

use once_cell::sync::Lazy;
use rand::rngs::StdRng;
use rand::SeedableRng;

use dusk_plonk::prelude::Error as PlonkError;
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, Hash, HashGadget};
use ff::Field;

static PUB_PARAMS: Lazy<PublicParameters> = Lazy::new(|| {
    let mut rng = StdRng::seed_from_u64(0xbeef);

    const CAPACITY: usize = 12;
    PublicParameters::setup(1 << CAPACITY, &mut rng)
        .expect("Cannot initialize Public Parameters")
});

fn compile_and_verify<C>(
    rng: &mut StdRng,
    circuit: &C,
    pi: &Vec<BlsScalar>,
) -> Result<(), PlonkError>
where
    C: Circuit,
{
    let label = b"hash-gadget-tester";
    let (prover, verifier) = Compiler::compile::<C>(&PUB_PARAMS, label)?;

    let (proof, _public_inputs) = prover.prove(rng, circuit)?;

    verifier.verify(&proof, pi)
}

// ----------------
// Test normal hash
// ----------------

#[derive(Debug)]
struct TestCircuit<const L: usize> {
    input: [BlsScalar; L],
    output: BlsScalar,
}

impl<const L: usize> Default for TestCircuit<L> {
    fn default() -> Self {
        Self {
            input: [BlsScalar::zero(); L],
            output: BlsScalar::zero(),
        }
    }
}

impl<const L: usize> TestCircuit<L> {
    pub fn random(rng: &mut StdRng) -> Self {
        // create random input
        let mut input = [BlsScalar::zero(); L];
        input
            .iter_mut()
            .for_each(|s| *s = BlsScalar::random(&mut *rng));

        // calculate expected hash output
        let output = Hash::digest(Domain::Other, &input)
            .expect("hash creation should not fail");

        Self {
            input,
            output: output[0],
        }
    }

    pub fn public_inputs(&self) -> Vec<BlsScalar> {
        [self.output].to_vec()
    }
}

impl<const L: usize> Circuit for TestCircuit<L> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        // append input to the circuit
        let mut input_witnesses = [Composer::ZERO; L];
        self.input
            .iter()
            .zip(input_witnesses.iter_mut())
            .for_each(|(i, w)| {
                *w = composer.append_witness(*i);
            });

        // check that the gadget result is as expected
        let gadget_output =
            HashGadget::digest(Domain::Other, composer, &input_witnesses)
                .expect("hash creation should not fail");
        composer.assert_equal_constant(gadget_output[0], 0, Some(self.output));

        Ok(())
    }
}

#[test]
fn test_gadget() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xbeef);

    // test for input of 3 scalar
    let circuit = TestCircuit::<3>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())?;

    // test for input of 5 scalar
    let circuit = TestCircuit::<5>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())?;

    // test for input of 15 scalar
    let circuit = TestCircuit::<15>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())
}

// -------------------
// Test truncated hash
// -------------------

#[derive(Debug)]
struct TestTruncatedCircuit<const L: usize> {
    input: [BlsScalar; L],
    output: JubJubScalar,
}

impl<const L: usize> Default for TestTruncatedCircuit<L> {
    fn default() -> Self {
        Self {
            input: [BlsScalar::zero(); L],
            output: JubJubScalar::zero(),
        }
    }
}

impl<const L: usize> TestTruncatedCircuit<L> {
    pub fn random(rng: &mut StdRng) -> Self {
        // create random input
        let mut input = [BlsScalar::zero(); L];
        input
            .iter_mut()
            .for_each(|s| *s = BlsScalar::random(&mut *rng));

        // calculate expected hash output
        let output = Hash::digest_truncated(Domain::Other, &input)
            .expect("hash creation should not fail");

        Self {
            input,
            output: output[0],
        }
    }

    pub fn public_inputs(&self) -> Vec<BlsScalar> {
        [self.output.into()].to_vec()
    }
}

impl<const L: usize> Circuit for TestTruncatedCircuit<L> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        // append input to the circuit
        let mut input_witnesses = [Composer::ZERO; L];
        self.input
            .iter()
            .zip(input_witnesses.iter_mut())
            .for_each(|(i, w)| {
                *w = composer.append_witness(*i);
            });

        // check that the gadget result is as expected
        let mut hash = HashGadget::new(Domain::Other);
        hash.update(&input_witnesses);
        let gadget_output = HashGadget::digest_truncated(
            Domain::Other,
            composer,
            &input_witnesses,
        )
        .expect("hash creation should not fail");
        composer.assert_equal_constant(
            gadget_output[0],
            0,
            Some(self.output.into()),
        );

        Ok(())
    }
}

#[test]
fn test_truncated_gadget() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xbeef);

    // test for input of 3 scalar
    let circuit = TestTruncatedCircuit::<3>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())?;

    // test for input of 5 scalar
    let circuit = TestTruncatedCircuit::<5>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())?;

    // test for input of 15 scalar
    let circuit = TestTruncatedCircuit::<15>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())
}

// --------------------
// Test multiple output
// --------------------

#[derive(Debug)]
struct MultipleOutputCircuit<const I: usize, const O: usize> {
    input: [BlsScalar; I],
    output: Vec<BlsScalar>,
}

impl<const I: usize, const O: usize> Default for MultipleOutputCircuit<I, O> {
    fn default() -> Self {
        Self {
            input: [BlsScalar::zero(); I],
            output: [BlsScalar::zero(); O].to_vec(),
        }
    }
}

impl<const I: usize, const O: usize> MultipleOutputCircuit<I, O> {
    pub fn random(rng: &mut StdRng) -> Self {
        // create random input
        let mut input = [BlsScalar::zero(); I];
        input
            .iter_mut()
            .for_each(|s| *s = BlsScalar::random(&mut *rng));

        // calculate expected hash output
        let mut hash = Hash::new(Domain::Other);
        hash.update(&input);
        hash.output_len(O);
        let output = hash.finalize().expect("Hash creation should pass");

        assert_eq!(output.len(), O);

        Self { input, output }
    }

    pub fn public_inputs(&self) -> Vec<BlsScalar> {
        self.output.clone()
    }
}

impl<const I: usize, const O: usize> Circuit for MultipleOutputCircuit<I, O> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        // append input to the circuit
        let mut input_witnesses = [Composer::ZERO; I];
        self.input
            .iter()
            .zip(input_witnesses.iter_mut())
            .for_each(|(i, w)| {
                *w = composer.append_witness(*i);
            });

        // add hash-gadget to the circuit
        let mut hash = HashGadget::new(Domain::Other);
        hash.output_len(O);
        hash.update(&input_witnesses);
        let gadget_output = hash
            .finalize(composer)
            .expect("hash creation should not fail");

        assert_eq!(gadget_output.len(), self.output.len());

        // assert that gadget output is equal to expected output
        self.output
            .iter()
            .zip(gadget_output)
            .for_each(|(o, g)| composer.assert_equal_constant(g, 0, Some(*o)));

        Ok(())
    }
}

#[test]
fn test_multiple_output() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xbeef);

    // test for input of 3 scalar
    let circuit = MultipleOutputCircuit::<3, 3>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())?;

    // test for input of 5 scalar
    let circuit = MultipleOutputCircuit::<5, 2>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())?;

    // test for input of 15 scalar
    let circuit = MultipleOutputCircuit::<4, 7>::random(&mut rng);
    compile_and_verify(&mut rng, &circuit, &circuit.public_inputs())
}
