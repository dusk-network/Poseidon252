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
//! - Permutation `WIDTH` is 5 field elements
//! - 8 full rounds: 4 full rounds at the beginning and 4 full rounds at the
//!   end, and each full round has `WIDTH` quintic S-Boxes.
//! - 59 partial rounds: each partial round has a quintic S-Box and `WIDTH - 1`
//!   identity functions.
//! - 960 round constants
//! - Round constants for the full rounds are generated using [this algorithm](https://extgit.iaik.tugraz.at/krypto/hadesmimc/blob/master/code/calc_round_numbers.py)
//! - The MDS matrix is a cauchy matrix, the method used to generate it, is
//!   noted in section "Concrete Instantiations Poseidon and Starkad"

mod mds_matrix;
mod round_constants;
mod strategies;

use mds_matrix::MDS_MATRIX;
use round_constants::ROUND_CONSTANTS;

const TOTAL_FULL_ROUNDS: usize = 8;

const PARTIAL_ROUNDS: usize = 59;

const CONSTANTS: usize = 960;

/// The amount of field elements that fit into the hades permutation container
pub const WIDTH: usize = 5;

#[cfg(feature = "zk")]
pub use strategies::GadgetStrategy;
pub use strategies::{ScalarStrategy, Strategy};

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
