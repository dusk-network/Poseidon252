// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_safe::Safe;

use super::Hades;
use crate::hades::{MDS_MATRIX, ROUND_CONSTANTS, WIDTH};

/// An implementation of the [`Permutation`] for `BlsScalar` as input values.
#[derive(Default)]
pub(crate) struct ScalarPermutation();

impl ScalarPermutation {
    /// Constructs a new `ScalarPermutation`.
    pub fn new() -> Self {
        Self()
    }
}

impl Safe<BlsScalar, WIDTH> for ScalarPermutation {
    fn permute(&mut self, state: &mut [BlsScalar; WIDTH]) {
        self.perm(state);
    }

    fn tag(&mut self, input: &[u8]) -> BlsScalar {
        BlsScalar::hash_to_scalar(input.as_ref())
    }

    fn add(&mut self, right: &BlsScalar, left: &BlsScalar) -> BlsScalar {
        right + left
    }
}

impl Hades<BlsScalar> for ScalarPermutation {
    fn add_round_constants(
        &mut self,
        round: usize,
        state: &mut [BlsScalar; WIDTH],
    ) {
        state
            .iter_mut()
            .enumerate()
            .for_each(|(i, s)| *s += ROUND_CONSTANTS[round][i]);
    }

    fn quintic_s_box(&mut self, value: &mut BlsScalar) {
        *value = value.square().square() * *value;
    }

    fn mul_matrix(&mut self, _round: usize, state: &mut [BlsScalar; WIDTH]) {
        let mut result = [BlsScalar::zero(); WIDTH];

        for (j, value) in state.iter().enumerate() {
            for k in 0..WIDTH {
                result[k] += MDS_MATRIX[k][j] * value;
            }
        }

        state.copy_from_slice(&result);
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
    use super::*;

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
}
