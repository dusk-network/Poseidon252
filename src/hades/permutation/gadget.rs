// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_plonk::prelude::*;
use dusk_safe::Safe;

use crate::hades::{MDS_MATRIX, ROUND_CONSTANTS, WIDTH};

use super::Hades;

/// An implementation for the [`Hades`]permutation operating on [`Witness`]es.
/// Requires a reference to a `ConstraintSystem`.
pub(crate) struct GadgetPermutation<'a> {
    /// A reference to the constraint system used by the gadgets
    composer: &'a mut Composer,
}

impl<'a> GadgetPermutation<'a> {
    /// Constructs a new `GadgetPermutation` with the constraint system.
    pub fn new(composer: &'a mut Composer) -> Self {
        Self { composer }
    }
}

impl<'a> Safe<Witness, WIDTH> for GadgetPermutation<'a> {
    fn permute(&mut self, state: &mut [Witness; WIDTH]) {
        self.perm(state);
    }

    fn tag(&mut self, input: &[u8]) -> Witness {
        let tag = BlsScalar::hash_to_scalar(input.as_ref());
        self.composer.append_witness(tag)
    }

    fn add(&mut self, right: &Witness, left: &Witness) -> Witness {
        let constraint = Constraint::new().left(1).a(*left).right(1).b(*right);
        self.composer.gate_add(constraint)
    }
}

impl<'a> Hades<Witness> for GadgetPermutation<'a> {
    fn add_round_constants(
        &mut self,
        round: usize,
        state: &mut [Witness; WIDTH],
    ) {
        // To safe constraints we only add the constants here in the first
        // round. The remaining constants will be added in the matrix
        // multiplication.
        if round == 0 {
            state.iter_mut().enumerate().for_each(|(i, w)| {
                let constant = ROUND_CONSTANTS[0][i];
                let constraint =
                    Constraint::new().left(1).a(*w).constant(constant);

                *w = self.composer.gate_add(constraint);
            });
        }
    }

    fn quintic_s_box(&mut self, value: &mut Witness) {
        let constraint = Constraint::new().mult(1).a(*value).b(*value);
        let v2 = self.composer.gate_mul(constraint);

        let constraint = Constraint::new().mult(1).a(v2).b(v2);
        let v4 = self.composer.gate_mul(constraint);

        let constraint = Constraint::new().mult(1).a(v4).b(*value);
        *value = self.composer.gate_mul(constraint);
    }

    /// Adds a constraint for each matrix coefficient multiplication
    fn mul_matrix(&mut self, round: usize, state: &mut [Witness; WIDTH]) {
        let mut result = [Composer::ZERO; WIDTH];

        // Implementation optimized for WIDTH = 5
        //
        // The resulting array `r` will be defined as
        // r[x] = sum_{j=0..WIDTH} ( MDS[x][j] * state[j] ) + c
        // with c being the constant for the next round.
        //
        // q_l = MDS[x][0]
        // q_r = MDS[x][1]
        // q_4 = MDS[x][2]
        // w_l = state[0]
        // w_r = state[1]
        // w_4 = state[2]
        // r[x] = q_l · w_l + q_r · w_r + q_4 · w_4;
        //
        // q_l = MDS[x][3]
        // q_r = MDS[x][4]
        // q_4 = 1
        // w_l = state[3]
        // w_r = state[4]
        // w_4 = r[x]
        // r[x] = q_l · w_l + q_r · w_r + q_4 · w_4 + c;
        for j in 0..WIDTH {
            // c is the next round's constant and hence zero for the last round.
            let c = match round + 1 < Self::ROUNDS {
                true => ROUND_CONSTANTS[round + 1][j],
                false => BlsScalar::zero(),
            };

            let constraint = Constraint::new()
                .left(MDS_MATRIX[j][0])
                .a(state[0])
                .right(MDS_MATRIX[j][1])
                .b(state[1])
                .fourth(MDS_MATRIX[j][2])
                .d(state[2]);

            result[j] = self.composer.gate_add(constraint);

            let constraint = Constraint::new()
                .left(MDS_MATRIX[j][3])
                .a(state[3])
                .right(MDS_MATRIX[j][4])
                .b(state[4])
                .fourth(1)
                .d(result[j])
                .constant(c);

            result[j] = self.composer.gate_add(constraint);
        }

        state.copy_from_slice(&result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hades::ScalarPermutation;

    use core::result::Result;
    use ff::Field;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[derive(Default)]
    struct TestCircuit {
        i: [BlsScalar; WIDTH],
        o: [BlsScalar; WIDTH],
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let zero = Composer::ZERO;

            let mut perm: [Witness; WIDTH] = [zero; WIDTH];

            let mut i_wit: [Witness; WIDTH] = [zero; WIDTH];
            self.i.iter().zip(i_wit.iter_mut()).for_each(|(i, w)| {
                *w = composer.append_witness(*i);
            });

            let mut o_wit: [Witness; WIDTH] = [zero; WIDTH];
            self.o.iter().zip(o_wit.iter_mut()).for_each(|(o, w)| {
                *w = composer.append_witness(*o);
            });

            // Apply Hades gadget permutation.
            GadgetPermutation::new(composer).permute(&mut i_wit);

            // Copy the result of the permutation into the perm.
            perm.copy_from_slice(&i_wit);

            // Check that the Gadget perm results = BlsScalar perm results
            i_wit.iter().zip(o_wit.iter()).for_each(|(p, o)| {
                composer.assert_equal(*p, *o);
            });

            Ok(())
        }
    }

    /// Generate a random input and perform a permutation
    fn hades() -> ([BlsScalar; WIDTH], [BlsScalar; WIDTH]) {
        let mut input = [BlsScalar::zero(); WIDTH];

        let mut rng = StdRng::seed_from_u64(0xbeef);

        input
            .iter_mut()
            .for_each(|s| *s = BlsScalar::random(&mut rng));

        let mut output = [BlsScalar::zero(); WIDTH];

        output.copy_from_slice(&input);
        ScalarPermutation::new().permute(&mut output);

        (input, output)
    }

    /// Setup the test circuit prover and verifier
    fn setup() -> Result<(Prover, Verifier), Error> {
        const CAPACITY: usize = 1 << 10;

        let mut rng = StdRng::seed_from_u64(0xbeef);

        let pp = PublicParameters::setup(CAPACITY, &mut rng)?;
        let label = b"hades_gadget_tester";

        Compiler::compile::<TestCircuit>(&pp, label)
    }

    #[test]
    fn preimage() -> Result<(), Error> {
        let (prover, verifier) = setup()?;

        let (i, o) = hades();

        let circuit = TestCircuit { i, o };
        let mut rng = StdRng::seed_from_u64(0xbeef);

        // Proving
        let (proof, public_inputs) = prover.prove(&mut rng, &circuit)?;

        // Verifying
        verifier.verify(&proof, &public_inputs)?;

        Ok(())
    }

    #[test]
    fn preimage_constant() -> Result<(), Error> {
        let (prover, verifier) = setup()?;

        // Prepare input & output
        let i = [BlsScalar::from(5000u64); WIDTH];
        let mut o = [BlsScalar::from(5000u64); WIDTH];
        ScalarPermutation::new().permute(&mut o);

        let circuit = TestCircuit { i, o };
        let mut rng = StdRng::seed_from_u64(0xbeef);

        // Proving
        let (proof, public_inputs) = prover.prove(&mut rng, &circuit)?;

        // Verifying
        verifier.verify(&proof, &public_inputs)?;

        Ok(())
    }

    #[test]
    fn preimage_fails() -> Result<(), Error> {
        let (prover, _) = setup()?;

        // Generate [31, 0, 0, 0, 0] as real input to the perm but build the
        // proof with [31, 31, 31, 31, 31]. This should fail on verification
        // since the Proof contains incorrect statements.
        let x_scalar = BlsScalar::from(31u64);

        let mut i = [BlsScalar::zero(); WIDTH];
        i[1] = x_scalar;

        let mut o = [BlsScalar::from(31u64); WIDTH];
        ScalarPermutation::new().permute(&mut o);

        let circuit = TestCircuit { i, o };
        let mut rng = StdRng::seed_from_u64(0xbeef);

        // Proving should fail
        assert!(
            prover.prove(&mut rng, &circuit).is_err(),
            "proving should fail since the circuit is invalid"
        );

        Ok(())
    }
}
