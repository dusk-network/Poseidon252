// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

use crate::hades::{Strategy, MDS_MATRIX, WIDTH};

/// Implements a Hades252 strategy for `BlsScalar` as input values.
#[derive(Default)]
pub struct ScalarStrategy {}

impl ScalarStrategy {
    /// Constructs a new `ScalarStrategy`.
    pub fn new() -> Self {
        Default::default()
    }
}

impl Strategy<BlsScalar> for ScalarStrategy {
    fn add_round_key<'b, I>(
        &mut self,
        constants: &mut I,
        words: &mut [BlsScalar],
    ) where
        I: Iterator<Item = &'b BlsScalar>,
    {
        words.iter_mut().for_each(|w| {
            *w += Self::next_c(constants);
        });
    }

    fn quintic_s_box(&mut self, value: &mut BlsScalar) {
        *value = value.square().square() * *value;
    }

    fn mul_matrix<'b, I>(
        &mut self,
        _constants: &mut I,
        values: &mut [BlsScalar],
    ) where
        I: Iterator<Item = &'b BlsScalar>,
    {
        let mut result = [BlsScalar::zero(); WIDTH];

        for (j, value) in values.iter().enumerate().take(WIDTH) {
            for k in 0..WIDTH {
                result[k] += MDS_MATRIX[k][j] * value;
            }
        }

        values.copy_from_slice(&result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perm(values: &mut [BlsScalar]) {
        let mut strategy = ScalarStrategy::new();
        strategy.perm(values);
    }

    #[test]
    fn hades_det() {
        let mut x = [BlsScalar::from(17u64); WIDTH];
        let mut y = [BlsScalar::from(17u64); WIDTH];
        let mut z = [BlsScalar::from(19u64); WIDTH];

        perm(&mut x);
        perm(&mut y);
        perm(&mut z);

        assert_eq!(x, y);
        assert_ne!(x, z);
    }
}
