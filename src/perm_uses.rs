// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The `pad` module implements the padding algorithm on the Poseidon hash.

use dusk_bls12_381::BlsScalar;
use hades252::strategies::{ScalarStrategy, Strategy};

/// Takes in one BlsScalar and outputs 2.
/// This function is fixed.
pub fn two_outputs(message: BlsScalar) -> [BlsScalar; 2] {
    const CAPACITY: BlsScalar = BlsScalar::from_raw([0, 1, 0, 0]);

    let mut words = [BlsScalar::zero(); hades252::WIDTH];

    words[0] = CAPACITY;
    words[1] = message;

    // Since we do a fixed_length hash, `words` is always
    // the size of `WIDTH`. Therefore, we can simply do
    // the permutation and return the desired results.
    ScalarStrategy::new().perm(&mut words);

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
