// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

use crate::hades::{Permutation as HadesPermutation, MDS_MATRIX, WIDTH};

/// State that implements the [`HadesPermutation`] for `BlsScalar` as input
/// values.
#[derive(Default)]
pub(crate) struct ScalarPermutation {}

impl ScalarPermutation {
    /// Constructs a new `ScalarPermutation`.
    pub fn new() -> Self {
        Default::default()
    }
}

impl HadesPermutation<BlsScalar> for ScalarPermutation {
    fn add_round_key<'b, I>(
        &mut self,
        constants: &mut I,
        state: &mut [BlsScalar; WIDTH],
    ) where
        I: Iterator<Item = &'b BlsScalar>,
    {
        state.iter_mut().for_each(|w| {
            *w += Self::next_c(constants);
        });
    }

    fn quintic_s_box(&mut self, value: &mut BlsScalar) {
        *value = value.square().square() * *value;
    }

    fn mul_matrix<'b, I>(
        &mut self,
        _constants: &mut I,
        state: &mut [BlsScalar; WIDTH],
    ) where
        I: Iterator<Item = &'b BlsScalar>,
    {
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
