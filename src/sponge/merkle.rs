// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "alloc")]
use dusk_hades::GadgetStrategy;
use dusk_hades::{ScalarStrategy, Strategy, WIDTH};

use dusk_plonk::prelude::*;

// Computes the tag from the domain-separator and arity. Output lenght is
// set to 1.
// Encoding:
// first 16 bits is set to arity with the MSB set to 1
// next 16 bits is set to 1 (our output length)
// last 32 bits are set to the domain separator, which is the bitmask of the
// leaves that are present in the level
fn tag<const A: usize>(dom_sep: u32) -> u64 {
    let mut tag: u64 = 1 << 15;
    tag |= A as u64;
    tag <<= 16;

    tag |= 1;
    tag <<= 16;

    tag |= dom_sep as u64;
    tag
}

/// This `hash` function is specialized for hashing the levels of a merkle tree
/// with arity `A` using the `Hades` ScalarStrategy.
///
/// As the paper definition, the capacity `c` is 1, the rate `r` is `4`
/// (`dusk_hades::WIDTH - 1`) and the domain separator is the bitmask of the
/// children that are present at the level (e.g. if there is only one child at
/// position 0, the LSB of the domain separator will be turned on). Due to the
/// domain separator being of type `u32`, `A` can be at most 32.
///
/// The first scalar of the state is reserved for the capacity and is set to the
/// tag which is calculated based on the arity of the tree and the domain
/// separator.
///
/// The other scalars of the state will have the scalars of the message added in
/// `r`-sized chunks, with a `Hades` permutation after each chunk addition.
///
/// If arity is not dividable by `r`, the padding values will be zeroes.
pub fn hash<const A: usize>(
    messages: &[BlsScalar; A],
    dom_sep: u32,
) -> BlsScalar {
    let mut h = ScalarStrategy::new();

    // initialize the state with the capacity
    let mut state = [BlsScalar::zero(); WIDTH];
    state[0] = BlsScalar::from(tag::<A>(dom_sep));

    messages.chunks(WIDTH - 1).for_each(|chunk| {
        state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
            *s += c;
        });
        h.perm(&mut state);
    });

    state[1]
}

/// Mirror the implementation of [`hash`] inside of a PLONK circuit.
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
/// [`hash`]: crate::sponge::hash
#[cfg(feature = "alloc")]
pub fn gadget<C, const A: usize>(
    composer: &mut C,
    messages: &[Witness; A],
    dom_sep: u32,
) -> Witness
where
    C: Composer,
{
    // initialize the state with the capacity
    let mut state = [C::ZERO; WIDTH];
    state[0] = composer.append_witness(BlsScalar::from(tag::<A>(dom_sep)));

    messages.chunks(WIDTH - 1).for_each(|chunk| {
        state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
            let constraint = Constraint::new().left(1).a(*s).right(1).b(*c);
            *s = composer.gate_add(constraint);
        });
        GadgetStrategy::gadget(composer, &mut state);
    });

    state[1]
}
