// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module contains an implementation of the `Hades252` permutation
//! algorithm specifically designed to work outside of Rank 1 Constraint Systems
//! (R1CS) or other custom Constraint Systems such as Add/Mul/Custom plonk
//! gate-circuits.
//!
//! The inputs of the permutation function have to be explicitly over the
//! scalar Field of the bls12_381 curve so over a modulus
//! `p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.

use dusk_bls12_381::BlsScalar;

use crate::hades::{
    FULL_ROUNDS, MDS_MATRIX, OPT_ROUND_CONSTANTS, PARTIAL_ROUNDS,
    PRE_SPARSE_MATRIX, SPARSE_MATRICES, WIDTH,
};

/// Hades permutation struct operating in a plonk-circuit.
#[cfg(feature = "zk")]
pub(crate) mod gadget;

/// Hades permutation struct operating on [`BlsScalar`].
pub(crate) mod scalar;

/// Defines the Hades252 permutation algorithm.
///
/// This permutation is a 3-step process that:
/// - Applies half of the `FULL_ROUNDS` (which can be understood as linear ops).
/// - Applies the `PARTIAL_ROUNDS` (which can be understood as non-linear ops).
/// - Applies the other half of the `FULL_ROUNDS`.
///
/// This structure allows to minimize the number of non-linear ops while
/// maintaining the security.
pub(crate) trait Hades<T> {
    /// Computes `input ^ 5 + post_constant (mod p)`.
    ///
    /// `post_constant` is the compressed constant for the following round. The
    /// modulo is taken with respect to the scalar field of the bls12_381 curve
    /// `p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
    fn quintic_s_box(&mut self, value: &mut T, post_constant: BlsScalar);

    /// Multiply the reversed MDS matrix with the state.
    fn mul_matrix(&mut self, state: &mut [T; WIDTH]);

    /// Multiply the pre-sparse matrix with the state.
    fn mul_pre_sparse_matrix(&mut self, state: &mut [T; WIDTH]);

    /// Applies the first optimized full round.
    fn apply_first_full_round(
        &mut self,
        constants_offset: &mut usize,
        state: &mut [T; WIDTH],
    );

    /// Applies all optimized partial rounds.
    fn apply_partial_rounds(
        &mut self,
        constants_offset: &mut usize,
        state: &mut [T; WIDTH],
    );

    /// Applies one optimized full round.
    fn apply_full_round(
        &mut self,
        round: usize,
        constants_offset: &mut usize,
        state: &mut [T; WIDTH],
        last_round: bool,
    ) {
        for (i, value) in state.iter_mut().enumerate() {
            let post_constant = match last_round {
                true => BlsScalar::zero(),
                false => OPT_ROUND_CONSTANTS[*constants_offset + i],
            };
            self.quintic_s_box(value, post_constant);
        }

        if !last_round {
            *constants_offset += WIDTH;
        }

        if round == FULL_ROUNDS / 2 - 1 {
            self.mul_pre_sparse_matrix(state);
        } else {
            self.mul_matrix(state);
        }
    }

    /// Applies one Hades permutation using the optimized Poseidon schedule.
    fn perm(&mut self, state: &mut [T; WIDTH]) {
        state.reverse();

        let mut constants_offset = 0;
        self.apply_first_full_round(&mut constants_offset, state);

        for round in 1..FULL_ROUNDS / 2 {
            self.apply_full_round(round, &mut constants_offset, state, false);
        }

        self.apply_partial_rounds(&mut constants_offset, state);

        for round in
            FULL_ROUNDS / 2 + PARTIAL_ROUNDS..FULL_ROUNDS + PARTIAL_ROUNDS - 1
        {
            self.apply_full_round(round, &mut constants_offset, state, false);
        }

        self.apply_full_round(
            FULL_ROUNDS + PARTIAL_ROUNDS - 1,
            &mut constants_offset,
            state,
            true,
        );

        debug_assert_eq!(constants_offset, OPT_ROUND_CONSTANTS.len());

        state.reverse();
    }

    /// Coefficient of the reversed MDS matrix.
    fn reversed_mds(row: usize, column: usize) -> BlsScalar {
        MDS_MATRIX[WIDTH - 1 - row][WIDTH - 1 - column]
    }

    /// Coefficient of the pre-sparse matrix.
    ///
    /// The optimized tables are stored for right multiplication of a row
    /// vector: `result[column] += state[row] * matrix[row][column]`. This is
    /// transposed relative to the dense matrix accessor above.
    fn pre_sparse(row: usize, column: usize) -> BlsScalar {
        PRE_SPARSE_MATRIX[row][column]
    }

    /// Coefficient of a sparse matrix.
    ///
    /// Like [`Hades::pre_sparse`], the sparse coefficients are stored for
    /// right multiplication of a row vector and are therefore transposed
    /// relative to [`Hades::reversed_mds`].
    fn sparse(round: usize, row: usize, column: usize) -> BlsScalar {
        match column {
            0 => SPARSE_MATRICES[round][row],
            _ if row == 0 => SPARSE_MATRICES[round][WIDTH + column - 1],
            _ if row == column => BlsScalar::one(),
            _ => BlsScalar::zero(),
        }
    }
}
