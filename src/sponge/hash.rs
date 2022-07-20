// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Sponge hash and gadget definition

use dusk_bls12_381::BlsScalar;
use dusk_hades::{ScalarStrategy, Strategy, WIDTH};

/// The `hash` function takes an arbitrary number of Scalars and returns the
/// hash, using the `Hades` ScalarStrategy.
///
/// As the paper definition, the capacity `c` is set to [`WIDTH`], and `r` is
/// set to `c - 1`.
///
/// Considering `r` is set to `c - 1`, the first bit will be the capacity and
/// will have no message addition, and the remainder bits of the permutation
/// will have the corresponding element of the chunk added.
///
/// The last permutation will append `1` to the message as a padding separator
/// value. The padding values will be zeroes. To avoid collision, the padding
/// will imply one additional permutation in case `|m|` is a multiple of `r`.
pub fn hash(messages: &[BlsScalar]) -> BlsScalar {
    let mut h = ScalarStrategy::new();
    let mut state = [BlsScalar::zero(); WIDTH];

    // If exists an `m` such as `m · (WIDTH - 1) == l`, then the last iteration
    // index should be `m - 1`.
    //
    // In other words, if `l` is a multiple of `WIDTH - 1`, then the last
    // iteration of the chunk should have an extra appended padding `1`.
    let l = messages.len();
    let m = l / (WIDTH - 1);
    let n = m * (WIDTH - 1);
    let last_iteration = if l == n {
        m.saturating_sub(1)
    } else {
        l / (WIDTH - 1)
    };

    messages
        .chunks(WIDTH - 1)
        .enumerate()
        .for_each(|(i, chunk)| {
            state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                *s += c;
            });

            // Last chunk should have an added `1` followed by zeroes, if there
            // is room for such
            if i == last_iteration && chunk.len() < WIDTH - 1 {
                state[chunk.len() + 1] += BlsScalar::one();

            // If its the last iteration and there is no available room to
            // append `1`, then there must be an extra permutation
            // for the padding
            } else if i == last_iteration {
                h.perm(&mut state);

                state[1] += BlsScalar::one();
            }

            h.perm(&mut state);
        });

    state[1]
}
