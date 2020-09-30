// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The `pad` module implements the padding algorithm on the Poseidon hash.
use super::pad::*;

use dusk_plonk::prelude::*;
use hades252::strategies::*;

/// Takes in one BlsScalar and outputs 2.
/// This function is fixed.
pub fn two_outputs(message: BlsScalar) -> [BlsScalar; 2] {
    let mut strategy = ScalarStrategy::new();

    // The value used to pad the words is zero.
    let padder = BlsScalar::zero();

    // The capacity is
    let capacity =
        BlsScalar::one() * BlsScalar::from(2 << 64 - 1) + BlsScalar::one();

    let mut words = pad_fixed_hash(capacity, message, padder);
    // Since we do a fixed_length hash, `words` is always
    // the size of `WIDTH`. Therefore, we can simply do
    // the permutation and return the desired results.
    strategy.perm(&mut words);

    [words[1], words[2]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_two_outputs() {
        let m = BlsScalar::random(&mut rand::thread_rng());

        let h = two_outputs(m);

        assert_eq!(h.len(), 2);
        assert_ne!(m, BlsScalar::zero());
        assert_ne!(h[0], BlsScalar::zero());
        assert_ne!(h[1], BlsScalar::zero());
    }

    #[test]
    fn same_result() {
        for _i in 0..100 {
            let m = BlsScalar::random(&mut rand::thread_rng());

            let h = two_outputs(m);
            let h_1 = two_outputs(m);

            assert_eq!(h, h_1);
        }
    }
}
