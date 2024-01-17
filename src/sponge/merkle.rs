// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Implement the sponge framework specialized for merkle trees where the input
//! length is constant and the output is always exactly one scalar.

use dusk_bls12_381::BlsScalar;

use crate::hades::{ScalarStrategy, Strategy, WIDTH};

#[cfg(feature = "zk")]
pub use zk::gadget;

// Computes the tag from the domain-separator and arity. Output length is
// set to 1.
// Encoding:
// first 32 bits are set to arity with the MSB set to 1
// last 32 bits is set to 1 (our output length)
fn tag<const A: usize>() -> u64 {
    let mut tag: u64 = 1 << 31;
    tag |= A as u64;
    tag <<= 32;

    tag |= 1;
    tag
}

/// This `hash` function is specialized for hashing the levels of a merkle tree
/// with arity `A` using the `Hades` ScalarStrategy.
/// NOTE: This hash should *only* be used for the hashing of the levels in a
/// merkle tree. When hashing variable length input (e.g. the data of the
/// leaves), use the generic `dusk_poseidon::sponge::hash` instead.
///
/// As per the paper definition, the capacity `c` is 1, the rate `r` is `4`,
/// which makes the permutation container exactly `5` elements long
/// (= `crate::hades::WIDTH`).
///
/// The capacity element is the first scalar of the state and is set to the tag
/// which is calculated based on the arity of the tree and appended to the
/// circuit as a constant.
///
/// The other scalars of the state will have the scalars of the message added in
/// `r`-sized chunks, with one `Hades` permutation after each chunk addition.
///
/// If `A` is not dividable by `r`, the padding values will be zeroes.
pub fn hash<const A: usize>(messages: &[BlsScalar; A]) -> BlsScalar {
    let mut h = ScalarStrategy::new();

    // initialize the state with zeros and set the first element to the tag
    let mut state = [BlsScalar::zero(); WIDTH];
    state[0] = BlsScalar::from(tag::<A>());

    // add the message scalars in r-sized chunks and permute the state after
    // each round
    messages.chunks(WIDTH - 1).for_each(|chunk| {
        state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
            *s += c;
        });
        h.perm(&mut state);
    });

    state[1]
}

#[cfg(feature = "zk")]
mod zk {
    use super::tag;

    use dusk_plonk::prelude::*;

    use crate::hades::{GadgetStrategy, WIDTH};

    /// Mirror the implementation of merkle [`hash`] inside of a PLONK circuit.
    ///
    /// The tag is dependent of the arity `A` as described in [`hash`] and
    /// appended to the circuit as a constant. This means that a pre-computed
    /// circuit over one arity can never be verified with a circuit of another
    /// arity.
    ///
    /// The returned value is the witness of the hash of the levels.
    pub fn gadget<const A: usize>(
        composer: &mut Composer,
        messages: &[Witness; A],
    ) -> Witness {
        // initialize the state with the capacity
        let mut state = [Composer::ZERO; WIDTH];
        state[0] = composer.append_witness(BlsScalar::from(tag::<A>()));

        messages.chunks(WIDTH - 1).for_each(|chunk| {
            state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                let constraint = Constraint::new().left(1).a(*s).right(1).b(*c);
                *s = composer.gate_add(constraint);
            });
            GadgetStrategy::gadget(composer, &mut state);
        });

        state[1]
    }
}
