// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Implement the sponge framework specialized for merkle trees where the input
//! length is constant and the output is always exactly one scalar.

#[cfg(feature = "merkle_tree")]
pub mod tree;

#[cfg(feature = "alloc")]
use dusk_hades::GadgetStrategy;
use dusk_hades::{ScalarStrategy, Strategy, WIDTH};

use dusk_plonk::prelude::*;

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
///
/// As the paper definition, the capacity `c` is 1, the rate `r` is `4`
/// (`dusk_hades::WIDTH - 1`).
///
/// The first scalar of the state is set to the tag which is calculated based on
/// the arity of the tree and appended to the circuit as a constant.
///
/// The other scalars of the state will have the scalars of the message added in
/// `r`-sized chunks, with a `Hades` permutation after each chunk addition.
///
/// If arity is not dividable by `r`, the padding values will be zeroes.
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

/// Mirror the implementation of merkle [`hash`] inside of a PLONK circuit.
///
/// The circuit will be defined by the length of `messages`. This means that a
/// pre-computed circuit will not behave generically for different messages
/// sizes.
///
/// The expected usage is the length of the message to be known publicly as the
/// circuit definition. Hence, the padding value `1` will be appended as a
/// circuit description.
///
/// The returned value is the hashed witness data computed as a variable.
///
/// [`hash`]: crate::sponge::merkle::hash
#[cfg(feature = "alloc")]
pub fn gadget<C, const A: usize>(
    composer: &mut C,
    messages: &[Witness; A],
) -> Witness
where
    C: Composer,
{
    // initialize the state with the capacity
    let mut state = [C::ZERO; WIDTH];
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
