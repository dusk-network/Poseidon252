// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

use crate::hades::{
    Permutation as HadesPermutation, MDS_MATRIX, ROUND_CONSTANTS, WIDTH,
};

/// An implementation of the [`HadesPermutation`] for `BlsScalar` as input
/// values.
#[derive(Default)]
pub(crate) struct ScalarPermutation {
    round: usize,
}

impl ScalarPermutation {
    /// Constructs a new `ScalarPermutation`.
    pub fn new() -> Self {
        Self { round: 0 }
    }
}

impl HadesPermutation<BlsScalar> for ScalarPermutation {
    fn increment_round(&mut self) {
        self.round += 1;
    }

    fn add_round_constants(&mut self, state: &mut [BlsScalar; WIDTH]) {
        state
            .iter_mut()
            .enumerate()
            // the rounds start counting at 1, so the respective round constants
            // are stored at index `round - 1`
            .for_each(|(i, s)| *s += ROUND_CONSTANTS[self.round - 1][i]);
    }

    fn quintic_s_box(&mut self, value: &mut BlsScalar) {
        *value = value.square().square() * *value;
    }

    fn mul_matrix(&mut self, state: &mut [BlsScalar; WIDTH]) {
        let mut result = [BlsScalar::zero(); WIDTH];

        for (j, value) in state.iter().enumerate() {
            for k in 0..WIDTH {
                result[k] += MDS_MATRIX[k][j] * value;
            }
        }

        state.copy_from_slice(&result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hades::permute;

    #[test]
    fn hades_det() {
        let mut x = [BlsScalar::from(17u64); WIDTH];
        let mut y = [BlsScalar::from(17u64); WIDTH];
        let mut z = [BlsScalar::from(19u64); WIDTH];

        permute(&mut x);
        permute(&mut y);
        permute(&mut z);

        assert_eq!(x, y);
        assert_ne!(x, z);
    }
}
