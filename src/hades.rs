// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Implementation of [Hades252](https://eprint.iacr.org/2019/458.pdf)
//! permutation algorithm over the Bls12-381 Scalar field.
//!
//! ## Parameters
//!
//! - `p = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`
//! - Permutation container `WIDTH` is 5 field elements
//! - 8 full rounds: 4 full rounds at the beginning and 4 full rounds at the
//!   end, and each full round has `WIDTH` quintic S-Boxes.
//! - 60 partial rounds: each partial round has `WIDTH - 1` identity function
//!   and one quintic S-Box.
//! - 340 round constants which are generated using [this algorithm](https://extgit.iaik.tugraz.at/krypto/hadesmimc/blob/master/code/calc_round_numbers.py)
//! - The MDS matrix is a cauchy matrix, the method used to generate it, is
//!   noted in section "Concrete Instantiations Poseidon and Starkad"

mod mds_matrix;
mod permutation;
mod round_constants;

use mds_matrix::MDS_MATRIX;
use round_constants::ROUND_CONSTANTS;

const FULL_ROUNDS: usize = 8;

const PARTIAL_ROUNDS: usize = 60;

/// The amount of field elements that fit into the hades permutation container
pub const WIDTH: usize = 5;

#[cfg(feature = "zk")]
pub(crate) use permutation::gadget::GadgetPermutation;
pub(crate) use permutation::scalar::ScalarPermutation;

const fn u64_from_buffer<const N: usize>(buf: &[u8; N], i: usize) -> u64 {
    u64::from_le_bytes([
        buf[i],
        buf[i + 1],
        buf[i + 2],
        buf[i + 3],
        buf[i + 4],
        buf[i + 5],
        buf[i + 6],
        buf[i + 7],
    ])
}

// Test the sponge with an internal hades permutation against some predefined
// input and output values. The sponge is initialized with the capacity element
// being zero and the padding is one `BlsScalar::one()`.
#[cfg(test)]
mod tests {
    extern crate std;
    use std::format;
    use std::vec;

    use dusk_bls12_381::BlsScalar;
    use dusk_bytes::ParseHexStr;
    use dusk_safe::{Call, Safe, Sponge};

    use crate::hades::{ScalarPermutation, WIDTH};

    #[derive(Default, Debug, Clone, Copy, PartialEq)]
    struct Test();

    impl Safe<BlsScalar, WIDTH> for Test {
        // apply hades permutation
        fn permute(&mut self, state: &mut [BlsScalar; WIDTH]) {
            ScalarPermutation::new().permute(state);
        }

        // the test in- and outputs have been created with the capacity element
        // (tag) being zero
        fn tag(&mut self, input: &[u8]) -> BlsScalar {
            let _ = input;
            BlsScalar::zero()
        }

        fn add(&mut self, right: &BlsScalar, left: &BlsScalar) -> BlsScalar {
            right + left
        }
    }

    impl Test {
        pub fn new() -> Self {
            Self()
        }
    }

    const TEST_INPUTS: [&str; 10] = [
        "bb67ed265bf1db490ded2e1ede55c0d14c55521509dc73f9c354e98ab76c9625",
        "7e74220084d75e10c89e9435d47bb5b8075991b2e29be3b84421dac3b1ee6007",
        "5ce5481a4d78cca03498f72761da1b9f1d2aa8fb300be39f0e4fe2534f9d4308",
        "b1e710e3c4a8c35154b0ce4e4f4af6f498ebd79f8e7cdf3150372c7501be250b",
        "33c9e2025f86b5d82149f1ab8e20a168fc3d99d09b48cbce0286db8752cc3306",
        "e98206bfdce791e4e5144079b997d4fc25006194b35655f0e48490b26e24ea35",
        "86d2a95cc552de8d5bb20bd4a407fee5ffdc314e93dfe6b2dc792bc71fd8cc2d",
        "4edd8307ce28a8c70963d20a7bc28df1e1720bbbc93878a18bd07fad7d51fa15",
        "eabc7a296704a68aa01f95adc85f6dd758b175745336d8fc795a17984024b21e",
        "cfc108673c93df305e31c283b9c767b7097ae4e174a223e0c24b15a67b701a3a",
    ];

    fn create_poseidon_hash(input: &[BlsScalar]) -> BlsScalar {
        let iopattern =
            vec![Call::Absorb(input.len()), Call::Absorb(1), Call::Squeeze(1)];

        let domain_sep = 0;
        let mut sponge = Sponge::start(Test::new(), iopattern, domain_sep)
            .expect("IO pattern should be valid");
        // absorb given input
        sponge
            .absorb(input.len(), input)
            .expect("Absorbtion of the input should work fine");
        // absorb padding of one BlsScalar::one()
        sponge
            .absorb(1, &[BlsScalar::one()])
            .expect("Absorbtion of padding should work fine");
        sponge.squeeze(1).expect("Squeezing should work fine");
        let output = sponge.finish().expect("Finish should work fine");
        output[0]
    }

    #[test]
    fn poseidon_hash() {
        let test_inputs: vec::Vec<BlsScalar> = TEST_INPUTS
            .iter()
            .map(|input| BlsScalar::from_hex_str(input).unwrap())
            .collect();

        assert_eq!(
        "0x26abf2d0476f154e69bf19740092fe36265680c294462b8e759ad73a99567dd5",
        format!("{:?}", create_poseidon_hash(&test_inputs[..3]))
    );

        assert_eq!(
        "0x1cc40219c7ec92919d6db7a41cd41953333a2ed544606daca182e4eaa6c7db2d",
        format!("{:?}", create_poseidon_hash(&test_inputs[..4]))
    );

        assert_eq!(
        "0x707c98a0e9a6e4832ac33ee08811bce122017a58dbbbf66a2f6fcdc69d45462d",
        format!("{:?}", create_poseidon_hash(&test_inputs[..5]))
    );

        assert_eq!(
        "0x26905a794d3d2fb0c3ed2276abc696c27a5bfdea7f106e596cbeedd86891c461",
        format!("{:?}", create_poseidon_hash(&test_inputs[..6]))
    );

        assert_eq!(
        "0x1b98a2c5f1fe54d21b5ce9bf0dcc99ea8784a64f3c544fa06d3f73569741006e",
        format!("{:?}", create_poseidon_hash(&test_inputs[..8]))
    );

        assert_eq!(
        "0x211b7ea21c9afca93dabdfbda8b2d5275b2dd802fed87bb431e98557c61667d2",
        format!("{:?}", create_poseidon_hash(&test_inputs[..10]))
    );
    }
}
