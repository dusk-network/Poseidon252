// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_plonk::prelude::*;

use crate::hades::{Strategy, MDS_MATRIX, WIDTH};

/// Implements a Hades252 strategy for `Witness` as input values.
/// Requires a reference to a `ConstraintSystem`.
pub struct GadgetStrategy<'a> {
    /// A reference to the constraint system used by the gadgets
    cs: &'a mut Composer,
    count: usize,
}

impl<'a> GadgetStrategy<'a> {
    /// Constructs a new `GadgetStrategy` with the constraint system.
    pub fn new(cs: &'a mut Composer) -> Self {
        GadgetStrategy { cs, count: 0 }
    }

    /// Perform the hades permutation on a plonk circuit
    pub fn gadget(composer: &'a mut Composer, x: &mut [Witness]) {
        let mut strategy = GadgetStrategy::new(composer);

        strategy.perm(x);
    }
}

impl AsMut<Composer> for GadgetStrategy<'_> {
    fn as_mut(&mut self) -> &mut Composer {
        self.cs
    }
}

impl<'a> Strategy<Witness> for GadgetStrategy<'a> {
    fn add_round_key<'b, I>(&mut self, constants: &mut I, words: &mut [Witness])
    where
        I: Iterator<Item = &'b BlsScalar>,
    {
        // Add only for the first round.
        //
        // The remainder ARC are performed with the constant appended
        // to the linear layer
        if self.count == 0 {
            words.iter_mut().for_each(|w| {
                let constant = Self::next_c(constants);
                let constraint =
                    Constraint::new().left(1).a(*w).constant(constant);

                *w = self.cs.gate_add(constraint);
            });
        }
    }

    fn quintic_s_box(&mut self, value: &mut Witness) {
        let constraint = Constraint::new().mult(1).a(*value).b(*value);
        let v2 = self.cs.gate_mul(constraint);

        let constraint = Constraint::new().mult(1).a(v2).b(v2);
        let v4 = self.cs.gate_mul(constraint);

        let constraint = Constraint::new().mult(1).a(v4).b(*value);
        *value = self.cs.gate_mul(constraint);
    }

    /// Adds a constraint for each matrix coefficient multiplication
    fn mul_matrix<'b, I>(&mut self, constants: &mut I, values: &mut [Witness])
    where
        I: Iterator<Item = &'b BlsScalar>,
    {
        let mut result = [Composer::ZERO; WIDTH];
        self.count += 1;

        // Implementation optimized for WIDTH = 5
        //
        // c is the next round constant.
        // For the partial round, it is added only for the last element
        //
        // The resulting array `r` will be defined as
        // r[x] = sum j 0..WIDTH ( MDS[x][j] * values[j] ) + c
        //
        // q_l = MDS[x][0]
        // q_r = MDS[x][1]
        // q_4 = MDS[x][2]
        // w_l = values[0]
        // w_r = values[1]
        // w_4 = values[2]
        // r[x] = q_l · w_l + q_r · w_r + q_4 · w_4;
        //
        // q_l = MDS[x][3]
        // q_r = MDS[x][4]
        // q_4 = 1
        // w_l = values[3]
        // w_r = values[4]
        // w_4 = r[x]
        // r[x] = q_l · w_l + q_r · w_r + q_4 · w_4 + c;
        for j in 0..WIDTH {
            let c = if self.count < Self::rounds() {
                Self::next_c(constants)
            } else {
                BlsScalar::zero()
            };

            let constraint = Constraint::new()
                .left(MDS_MATRIX[j][0])
                .a(values[0])
                .right(MDS_MATRIX[j][1])
                .b(values[1])
                .fourth(MDS_MATRIX[j][2])
                .d(values[2]);

            result[j] = self.cs.gate_add(constraint);

            let constraint = Constraint::new()
                .left(MDS_MATRIX[j][3])
                .a(values[3])
                .right(MDS_MATRIX[j][4])
                .b(values[4])
                .fourth(1)
                .d(result[j])
                .constant(c);

            result[j] = self.cs.gate_add(constraint);
        }

        values.copy_from_slice(&result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hades::ScalarStrategy;

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

            let mut i_var: [Witness; WIDTH] = [zero; WIDTH];
            self.i.iter().zip(i_var.iter_mut()).for_each(|(i, v)| {
                *v = composer.append_witness(*i);
            });

            let mut o_var: [Witness; WIDTH] = [zero; WIDTH];
            self.o.iter().zip(o_var.iter_mut()).for_each(|(o, v)| {
                *v = composer.append_witness(*o);
            });

            // Apply Hades gadget strategy.
            GadgetStrategy::gadget(composer, &mut i_var);

            // Copy the result of the permutation into the perm.
            perm.copy_from_slice(&i_var);

            // Check that the Gadget perm results = BlsScalar perm results
            i_var.iter().zip(o_var.iter()).for_each(|(p, o)| {
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
        ScalarStrategy::new().perm(&mut output);

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
        ScalarStrategy::new().perm(&mut o);

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
        ScalarStrategy::new().perm(&mut o);

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
