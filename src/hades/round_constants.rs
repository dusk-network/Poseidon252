// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module is designed to load the constants used as `ROUND_CONSTANTS`
//! from `assets/arc.bin`.
//!
//! The constants were originally computed using:
//! https://extgit.iaik.tugraz.at/krypto/hadesmimc/blob/master/code/calc_round_numbers.py
//! and then mapped onto `BlsScalar` in the Bls12_381 scalar field.

use dusk_bls12_381::BlsScalar;

use crate::hades::{FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};

const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;

/// `ROUND_CONSTANTS` consists on a static reference that points to the
/// pre-loaded 335 constant scalar of the bls12_381 curve.
///
/// These 335 `BlsScalar` constants are loaded from `assets/arc.bin`.
///
/// Check `assets/HOWTO.md` to see how we generated the constants.
pub const ROUND_CONSTANTS: [[BlsScalar; WIDTH]; ROUNDS] = {
    let bytes = include_bytes!("../../assets/arc.bin");

    // make sure that there are enough bytes for (WIDTH * ROUNDS) BlsScalar
    // stored under 'assets/arc.bin'
    if bytes.len() < WIDTH * ROUNDS * 32 {
        panic!("There are not enough round constants stored in 'assets/arc.bin', have a look at the HOWTO to generate enough constants.");
    }

    let mut cnst = [[BlsScalar::zero(); WIDTH]; ROUNDS];

    let mut i = 0;
    let mut j = 0;
    while i < WIDTH * ROUNDS * 32 {
        let a = super::u64_from_buffer(bytes, i);
        let b = super::u64_from_buffer(bytes, i + 8);
        let c = super::u64_from_buffer(bytes, i + 16);
        let d = super::u64_from_buffer(bytes, i + 24);

        cnst[j / WIDTH][j % WIDTH] = BlsScalar::from_raw([a, b, c, d]);
        j += 1;

        i += 32;
    }

    cnst
};

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_round_constants() {
        // Check each element is non-zero
        let zero = BlsScalar::zero();
        let has_zero = ROUND_CONSTANTS.iter().flatten().any(|&x| x == zero);
        for ctant in ROUND_CONSTANTS.iter().flatten() {
            let bytes = ctant.to_bytes();
            assert!(&BlsScalar::from_bytes(&bytes).unwrap() == ctant);
        }
        assert!(!has_zero);
    }
}
