// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_plonk::prelude::*;
use dusk_safe::Safe;

use super::Hades;
use crate::hades::{OPT_ROUND_CONSTANTS, PARTIAL_ROUNDS, WIDTH};

#[derive(Clone)]
struct LinearExpression {
    terms: Vec<(BlsScalar, Witness)>,
    constant: BlsScalar,
}

impl LinearExpression {
    fn zero() -> Self {
        Self {
            terms: Vec::new(),
            constant: BlsScalar::zero(),
        }
    }

    fn witness(witness: Witness) -> Self {
        let mut expr = Self::zero();
        expr.add_term(BlsScalar::one(), witness);
        expr
    }

    fn add_term(&mut self, coefficient: BlsScalar, witness: Witness) {
        if coefficient == BlsScalar::zero() {
            return;
        }

        if let Some((existing, _)) =
            self.terms.iter_mut().find(|(_, w)| *w == witness)
        {
            *existing += coefficient;
            if *existing == BlsScalar::zero() {
                self.terms.retain(|(coefficient, _)| {
                    *coefficient != BlsScalar::zero()
                });
            }
            return;
        }

        self.terms.push((coefficient, witness));
    }

    fn add_scaled_expression(
        &mut self,
        coefficient: BlsScalar,
        expression: &Self,
    ) {
        if coefficient == BlsScalar::zero() {
            return;
        }

        self.constant += coefficient * expression.constant;
        expression
            .terms
            .iter()
            .for_each(|(term_coefficient, witness)| {
                self.add_term(coefficient * term_coefficient, *witness);
            });
    }
}

/// An implementation for the [`Hades`] permutation operating on [`Witness`]es.
/// Requires a reference to a plonk circuit [`Composer`].
pub(crate) struct GadgetPermutation<'a> {
    /// A reference to the constraint system used by the gadgets
    composer: &'a mut Composer,
}

impl<'a> GadgetPermutation<'a> {
    /// Constructs a new `GadgetPermutation` with the constraint system.
    pub fn new(composer: &'a mut Composer) -> Self {
        Self { composer }
    }

    fn gate_add_expression(
        &mut self,
        terms: &[(BlsScalar, Witness)],
        constant: BlsScalar,
    ) -> Witness {
        let first_terms = terms.len().min(3);
        let mut constraint = Constraint::new().constant(constant);

        if let Some((coefficient, witness)) = terms[..first_terms].first() {
            constraint = constraint.left(*coefficient).a(*witness);
        }

        if let Some((coefficient, witness)) = terms[..first_terms].get(1) {
            constraint = constraint.right(*coefficient).b(*witness);
        }

        if let Some((coefficient, witness)) = terms[..first_terms].get(2) {
            constraint = constraint.fourth(*coefficient).d(*witness);
        }

        let mut witness = self.composer.gate_add(constraint);
        let mut offset = first_terms;

        while offset < terms.len() {
            let mut constraint = Constraint::new().left(1).a(witness);

            if let Some((coefficient, term_witness)) = terms.get(offset) {
                constraint = constraint.right(*coefficient).b(*term_witness);
            }

            if let Some((coefficient, term_witness)) = terms.get(offset + 1) {
                constraint = constraint.fourth(*coefficient).d(*term_witness);
            }

            witness = self.composer.gate_add(constraint);
            offset += 2;
        }

        witness
    }

    fn materialize_expression(
        &mut self,
        expression: &LinearExpression,
    ) -> Witness {
        match expression.terms.as_slice() {
            [] if expression.constant == BlsScalar::zero() => Composer::ZERO,
            [] if expression.constant == BlsScalar::one() => Composer::ONE,
            [] => self.composer.append_constant(expression.constant),
            [(coefficient, witness)]
                if *coefficient == BlsScalar::one()
                    && expression.constant == BlsScalar::zero() =>
            {
                *witness
            }
            terms => self.gate_add_expression(terms, expression.constant),
        }
    }

    fn quintic_s_box_with_constants(
        &mut self,
        value: &mut Witness,
        pre_constant: BlsScalar,
        post_constant: BlsScalar,
    ) {
        let pre_constant_squared = pre_constant * pre_constant;
        let constraint = Constraint::new()
            .mult(1)
            .left(pre_constant)
            .right(pre_constant)
            .a(*value)
            .b(*value)
            .constant(pre_constant_squared);
        let v2 = self.composer.gate_mul(constraint);

        let constraint = Constraint::new().mult(1).a(v2).b(v2);
        let v4 = self.composer.gate_mul(constraint);

        let constraint = Constraint::new()
            .mult(1)
            .left(pre_constant)
            .a(v4)
            .b(*value)
            .constant(post_constant);
        *value = self.composer.gate_mul(constraint);
    }

    fn apply_sparse_matrix_as_expressions(
        &mut self,
        round: usize,
        state: &mut [LinearExpression; WIDTH],
    ) {
        let previous_state = state.clone();
        let mut result: [LinearExpression; WIDTH] =
            core::array::from_fn(|_| LinearExpression::zero());

        for (i, expression) in previous_state.iter().enumerate() {
            result[0]
                .add_scaled_expression(Self::sparse(round, i, 0), expression);
        }

        for j in 1..WIDTH {
            result[j]
                .add_scaled_expression(BlsScalar::one(), &previous_state[j]);
            result[j].add_scaled_expression(
                Self::sparse(round, 0, j),
                &previous_state[0],
            );
        }

        *state = result;
    }
}

impl<'a> Safe<Witness, WIDTH> for GadgetPermutation<'a> {
    fn permute(&mut self, state: &mut [Witness; WIDTH]) {
        self.perm(state);
    }

    fn tag(&mut self, input: &[u8]) -> Witness {
        let tag = BlsScalar::hash_to_scalar(input);
        // append the tag as a constant
        self.composer.append_constant(tag)
    }

    fn add(&mut self, right: &Witness, left: &Witness) -> Witness {
        let constraint = Constraint::new().left(1).a(*left).right(1).b(*right);
        self.composer.gate_add(constraint)
    }
}

impl<'a> Hades<Witness> for GadgetPermutation<'a> {
    fn quintic_s_box(&mut self, value: &mut Witness, post_constant: BlsScalar) {
        self.quintic_s_box_with_constants(
            value,
            BlsScalar::zero(),
            post_constant,
        );
    }

    /// Adds constraints for a dense matrix multiplication.
    fn mul_matrix(&mut self, state: &mut [Witness; WIDTH]) {
        let mut result = [Composer::ZERO; WIDTH];

        // Implementation optimized for WIDTH = 5
        for (j, result) in result.iter_mut().enumerate() {
            let constraint = Constraint::new()
                .left(Self::reversed_mds(j, 0))
                .a(state[0])
                .right(Self::reversed_mds(j, 1))
                .b(state[1])
                .fourth(Self::reversed_mds(j, 2))
                .d(state[2]);

            let partial = self.composer.gate_add(constraint);

            let constraint = Constraint::new()
                .left(Self::reversed_mds(j, 3))
                .a(state[3])
                .right(Self::reversed_mds(j, 4))
                .b(state[4])
                .fourth(1)
                .d(partial);

            *result = self.composer.gate_add(constraint);
        }

        state.copy_from_slice(&result);
    }

    fn mul_pre_sparse_matrix(&mut self, state: &mut [Witness; WIDTH]) {
        let mut result = [Composer::ZERO; WIDTH];

        for (j, result) in result.iter_mut().enumerate() {
            let constraint = Constraint::new()
                .left(Self::pre_sparse(0, j))
                .a(state[0])
                .right(Self::pre_sparse(1, j))
                .b(state[1])
                .fourth(Self::pre_sparse(2, j))
                .d(state[2]);

            let partial = self.composer.gate_add(constraint);

            let constraint = Constraint::new()
                .left(Self::pre_sparse(3, j))
                .a(state[3])
                .right(Self::pre_sparse(4, j))
                .b(state[4])
                .fourth(1)
                .d(partial);

            *result = self.composer.gate_add(constraint);
        }

        state.copy_from_slice(&result);
    }

    fn apply_first_full_round(
        &mut self,
        constants_offset: &mut usize,
        state: &mut [Witness; WIDTH],
    ) {
        for (i, value) in state.iter_mut().enumerate() {
            self.quintic_s_box_with_constants(
                value,
                OPT_ROUND_CONSTANTS[i],
                OPT_ROUND_CONSTANTS[WIDTH + i],
            );
        }
        *constants_offset = WIDTH * 2;

        self.mul_matrix(state);
    }

    fn apply_partial_rounds(
        &mut self,
        constants_offset: &mut usize,
        state: &mut [Witness; WIDTH],
    ) {
        let mut expression_state: [LinearExpression; WIDTH] =
            core::array::from_fn(|i| LinearExpression::witness(state[i]));

        for round in 0..PARTIAL_ROUNDS {
            let mut sbox_input =
                self.materialize_expression(&expression_state[0]);

            self.quintic_s_box(
                &mut sbox_input,
                OPT_ROUND_CONSTANTS[*constants_offset],
            );
            *constants_offset += 1;

            expression_state[0] = LinearExpression::witness(sbox_input);
            self.apply_sparse_matrix_as_expressions(
                round,
                &mut expression_state,
            );

            if round % 2 == 1 || round == PARTIAL_ROUNDS - 1 {
                for i in 0..WIDTH {
                    state[i] =
                        self.materialize_expression(&expression_state[i]);
                    expression_state[i] = LinearExpression::witness(state[i]);
                }
            }
        }
    }
}

#[cfg(feature = "encryption")]
impl dusk_safe::Encryption<Witness, WIDTH> for GadgetPermutation<'_> {
    fn subtract(&mut self, minuend: &Witness, subtrahend: &Witness) -> Witness {
        let constraint = Constraint::new()
            .left(1)
            .a(*minuend)
            .right(-BlsScalar::one())
            .b(*subtrahend);
        self.composer.gate_add(constraint)
    }

    fn is_equal(&mut self, lhs: &Witness, rhs: &Witness) -> bool {
        self.composer.assert_equal(*lhs, *rhs);
        // for the encryption to work we need to return true here, the proof
        // creation will fail at a later point if the above assertion isn't met
        true
    }
}

#[cfg(test)]
mod tests {
    use core::result::Result;

    use ff::Field;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;
    use crate::hades::ScalarPermutation;

    #[derive(Default)]
    struct TestCircuit {
        i: [BlsScalar; WIDTH],
        o: [BlsScalar; WIDTH],
    }

    impl Circuit for TestCircuit {
        fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
            let zero = Composer::ZERO;

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
