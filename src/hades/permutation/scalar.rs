// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_safe::Safe;

use super::Hades;
use crate::hades::WIDTH;

/// An implementation of the [`Permutation`] for `BlsScalar` as input values.
#[derive(Default)]
pub(crate) struct ScalarPermutation();

impl ScalarPermutation {
    /// Constructs a new `ScalarPermutation`.
    pub fn new() -> Self {
        Self()
    }

    fn add_round_constants(
        constants: &[BlsScalar],
        state: &mut [BlsScalar; WIDTH],
    ) {
        state
            .iter_mut()
            .zip(constants)
            .for_each(|(state, constant)| *state += constant);
    }

    fn apply_partial_round(
        &mut self,
        round: usize,
        constants_offset: &mut usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        self.quintic_s_box(
            &mut state[0],
            crate::hades::OPT_ROUND_CONSTANTS[*constants_offset],
        );
        *constants_offset += 1;
        self.mul_sparse_matrix(round, state);
    }

    fn mul_sparse_matrix(
        &mut self,
        round: usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        let mut result = [BlsScalar::zero(); WIDTH];

        for (i, value) in state.iter().enumerate() {
            result[0] += Self::sparse(round, i, 0) * value;
        }

        for j in 1..WIDTH {
            result[j] = state[j] + Self::sparse(round, 0, j) * state[0];
        }

        state.copy_from_slice(&result);
    }
}

impl Safe<BlsScalar, WIDTH> for ScalarPermutation {
    fn permute(&mut self, state: &mut [BlsScalar; WIDTH]) {
        self.perm(state);
    }

    fn tag(&mut self, input: &[u8]) -> BlsScalar {
        BlsScalar::hash_to_scalar(input)
    }

    fn add(&mut self, right: &BlsScalar, left: &BlsScalar) -> BlsScalar {
        right + left
    }
}

impl Hades<BlsScalar> for ScalarPermutation {
    fn quintic_s_box(
        &mut self,
        value: &mut BlsScalar,
        post_constant: BlsScalar,
    ) {
        *value = value.square().square() * *value + post_constant;
    }

    fn mul_matrix(&mut self, state: &mut [BlsScalar; WIDTH]) {
        let mut result = [BlsScalar::zero(); WIDTH];

        for (j, value) in state.iter().enumerate() {
            for (k, result) in result.iter_mut().enumerate() {
                *result += Self::reversed_mds(k, j) * value;
            }
        }

        state.copy_from_slice(&result);
    }

    fn mul_pre_sparse_matrix(&mut self, state: &mut [BlsScalar; WIDTH]) {
        let mut result = [BlsScalar::zero(); WIDTH];

        for (j, result) in result.iter_mut().enumerate() {
            for (i, value) in state.iter().enumerate() {
                *result += Self::pre_sparse(i, j) * value;
            }
        }

        state.copy_from_slice(&result);
    }

    fn apply_first_full_round(
        &mut self,
        constants_offset: &mut usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        Self::add_round_constants(
            &crate::hades::OPT_ROUND_CONSTANTS[..WIDTH],
            state,
        );
        *constants_offset += WIDTH;
        self.apply_full_round(0, constants_offset, state, false);
    }

    fn apply_partial_rounds(
        &mut self,
        constants_offset: &mut usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        for round in 0..crate::hades::PARTIAL_ROUNDS {
            self.apply_partial_round(round, constants_offset, state);
        }
    }
}

#[cfg(feature = "encryption")]
impl dusk_safe::Encryption<BlsScalar, WIDTH> for ScalarPermutation {
    fn subtract(
        &mut self,
        minuend: &BlsScalar,
        subtrahend: &BlsScalar,
    ) -> BlsScalar {
        minuend - subtrahend
    }

    fn is_equal(&mut self, lhs: &BlsScalar, rhs: &BlsScalar) -> bool {
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    use super::*;
    use crate::hades::round_constants::ROUND_CONSTANTS;
    use crate::hades::{FULL_ROUNDS, MDS_MATRIX, PARTIAL_ROUNDS};

    #[test]
    fn hades_det() {
        let mut x = [BlsScalar::from(17u64); WIDTH];
        let mut y = [BlsScalar::from(17u64); WIDTH];
        let mut z = [BlsScalar::from(19u64); WIDTH];

        ScalarPermutation::new().permute(&mut x);
        ScalarPermutation::new().permute(&mut y);
        ScalarPermutation::new().permute(&mut z);

        assert_eq!(x, y);
        assert_ne!(x, z);
    }

    fn legacy_quintic_s_box(value: &mut BlsScalar) {
        *value = value.square().square() * *value;
    }

    fn legacy_mul_matrix(state: &mut [BlsScalar; WIDTH]) {
        let mut result = [BlsScalar::zero(); WIDTH];

        for (j, value) in state.iter().enumerate() {
            for (k, result) in result.iter_mut().enumerate() {
                *result += MDS_MATRIX[k][j] * value;
            }
        }

        state.copy_from_slice(&result);
    }

    fn legacy_permute(state: &mut [BlsScalar; WIDTH]) {
        for round in 0..FULL_ROUNDS / 2 {
            for (i, value) in state.iter_mut().enumerate() {
                *value += ROUND_CONSTANTS[round][i];
                legacy_quintic_s_box(value);
            }

            legacy_mul_matrix(state);
        }

        for round in FULL_ROUNDS / 2..FULL_ROUNDS / 2 + PARTIAL_ROUNDS {
            for (i, value) in state.iter_mut().enumerate() {
                *value += ROUND_CONSTANTS[round][i];
            }

            legacy_quintic_s_box(&mut state[WIDTH - 1]);
            legacy_mul_matrix(state);
        }

        for round in
            FULL_ROUNDS / 2 + PARTIAL_ROUNDS..FULL_ROUNDS + PARTIAL_ROUNDS
        {
            for (i, value) in state.iter_mut().enumerate() {
                *value += ROUND_CONSTANTS[round][i];
                legacy_quintic_s_box(value);
            }

            legacy_mul_matrix(state);
        }
    }

    #[test]
    fn optimized_matches_legacy_permutation() {
        let mut inputs = Vec::new();
        inputs.push([BlsScalar::zero(); WIDTH]);
        inputs.push([BlsScalar::one(); WIDTH]);
        inputs.push([BlsScalar::from(17u64); WIDTH]);

        let mut rng = StdRng::seed_from_u64(0xdecaf);
        for _ in 0..32 {
            let mut input = [BlsScalar::zero(); WIDTH];
            for item in input.iter_mut() {
                *item = BlsScalar::from(rng.next_u64());
            }
            inputs.push(input);
        }

        for input in inputs {
            let mut legacy = input;
            let mut optimized = input;

            legacy_permute(&mut legacy);
            ScalarPermutation::new().permute(&mut optimized);

            assert_eq!(legacy, optimized);
        }
    }
}
