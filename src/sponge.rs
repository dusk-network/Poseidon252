// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "merkle")]
pub mod merkle;

pub mod truncated;

use dusk_bls12_381::BlsScalar;

use crate::hades::{permute, WIDTH};

#[cfg(feature = "zk")]
pub use zk::gadget;

/// The `hash` function takes an arbitrary number of Scalars and returns the
/// hash in the form of one scalar by using the `Hades` permutation of a state
/// of `WIDTH` scalars.
///
/// As the paper definition, the capacity `c` and the rate `r` equal `WIDTH`
/// and `c` is set to `1`.
///
/// The first scalar of the state will be the capacity and will have no message
/// addition. The remainder scalars of the state will be filled by adding
/// `r`-sized chunks of the input. After each addition of `r`-sized chunks the
/// state does one permutation.
///
/// The last permutation will append `1` to the message as a padding separator
/// value. The padding values will be zeroes. To avoid collision, the padding
/// will imply one additional permutation in case `len` is a multiple of `r`.
pub fn hash(messages: &[BlsScalar]) -> BlsScalar {
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
                permute(&mut state);

                state[1] += BlsScalar::one();
            }

            permute(&mut state);
        });

    state[1]
}

#[cfg(feature = "zk")]
mod zk {
    use crate::hades::{permute_gadget, WIDTH};
    use dusk_plonk::prelude::{Composer, Constraint, Witness};

    /// Mirror the implementation of [`hash`] inside of a PLONK circuit.
    ///
    /// The circuit will be defined by the length of `messages`. This means that
    /// the circuit description will be different for different messages sizes.
    ///
    /// The expected usage is the length of the message to be known publicly as
    /// the circuit definition. Hence, the padding value `1` will be
    /// appended as a constant in the circuit description.
    ///
    /// The returned value is the hashed witness data computed as a variable.
    ///
    /// [`hash`]: crate::sponge::hash
    pub fn gadget(composer: &mut Composer, messages: &[Witness]) -> Witness {
        let mut state = [Composer::ZERO; WIDTH];

        let l = messages.len();
        let m = l / (WIDTH - 1);
        let n = m * (WIDTH - 1);
        let last_iteration = if l == n { m - 1 } else { l / (WIDTH - 1) };

        messages
            .chunks(WIDTH - 1)
            .enumerate()
            .for_each(|(i, chunk)| {
                state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                    let constraint =
                        Constraint::new().left(1).a(*s).right(1).b(*c);

                    *s = composer.gate_add(constraint);
                });

                if i == last_iteration && chunk.len() < WIDTH - 1 {
                    let constraint = Constraint::new()
                        .left(1)
                        .a(state[chunk.len() + 1])
                        .constant(1);

                    state[chunk.len() + 1] = composer.gate_add(constraint);
                } else if i == last_iteration {
                    permute_gadget(composer, &mut state);

                    let constraint =
                        Constraint::new().left(1).a(state[1]).constant(1);

                    state[1] = composer.gate_add(constraint);
                }

                permute_gadget(composer, &mut state);
            });

        state[1]
    }
}
