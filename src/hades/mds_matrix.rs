// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;

use crate::hades::WIDTH;

/// Represents a `static reference` to the
/// `Maximum Distance Separable Matrix -> MDS_MATRIX`
/// of `(WIDTH x WIDTH)`.
///
/// This matrix is loaded from the `mds.bin` file where
/// is pre-computed and represented in bytes.
pub const MDS_MATRIX: [[BlsScalar; WIDTH]; WIDTH] = {
    let bytes = include_bytes!("../../assets/mds.bin");
    let mut mds = [[BlsScalar::zero(); WIDTH]; WIDTH];
    let mut k = 0;
    let mut i = 0;

    while i < WIDTH {
        let mut j = 0;
        while j < WIDTH {
            let a = super::u64_from_buffer(bytes, k);
            let b = super::u64_from_buffer(bytes, k + 8);
            let c = super::u64_from_buffer(bytes, k + 16);
            let d = super::u64_from_buffer(bytes, k + 24);
            k += 32;

            mds[i][j] = BlsScalar::from_raw([a, b, c, d]);
            j += 1;
        }
        i += 1;
    }

    mds
};
