// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module is designed to load the 960 constants used as `round_constants`
//! from `ark.bin`.
//!
//! The constants were originally computed using:
//! https://extgit.iaik.tugraz.at/krypto/hadesmimc/blob/master/code/calc_round_numbers.py
//! and then mapped onto `BlsScalar` in the Bls12_381 scalar field.

use dusk_bls12_381::BlsScalar;

use crate::hades::CONSTANTS;

/// `ROUND_CONSTANTS` constists on a static reference
/// that points to the pre-loaded 960 Fq constants.
///
/// This 960 `BlsScalar` constants are loaded from `ark.bin`
/// where all of the `BlsScalar`s are represented in buf.
///
/// This round constants have been taken from:
/// https://extgit.iaik.tugraz.at/krypto/hadesmimc/blob/master/code/calc_round_numbers.py
/// and then mapped onto `Fq` in the Ristretto scalar field.
pub const ROUND_CONSTANTS: [BlsScalar; CONSTANTS] = {
    let bytes = include_bytes!("../../assets/ark.bin");
    let mut cnst = [BlsScalar::zero(); CONSTANTS];

    let mut i = 0;
    let mut j = 0;
    while i < bytes.len() {
        let a = super::u64_from_buffer(bytes, i);
        let b = super::u64_from_buffer(bytes, i + 8);
        let c = super::u64_from_buffer(bytes, i + 16);
        let d = super::u64_from_buffer(bytes, i + 24);

        cnst[j] = BlsScalar::from_raw([a, b, c, d]);
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
        let has_zero = ROUND_CONSTANTS.iter().any(|&x| x == zero);
        for ctant in ROUND_CONSTANTS.iter() {
            let bytes = ctant.to_bytes();
            assert!(&BlsScalar::from_bytes(&bytes).unwrap() == ctant);
        }
        assert!(!has_zero);
    }
}
