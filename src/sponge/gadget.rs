// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_hades::{GadgetStrategy, WIDTH};

use dusk_plonk::prelude::*;

/// Mirror the implementation of [`super::sponge_hash`] inside of a PLONK circuit.
///
/// The circuit will be defined by the length of `messages`. This means that a
/// pre-computed circuit will not behave generically for different messages
/// sizes.
///
/// The expected usage is the length of the message to be known publically as
/// the circuit definition. Hence, the padding value `1` will be appended as a
/// circuit description.
///
/// The returned value is the hashed witness data computed as a variable.
pub fn gadget(composer: &mut TurboComposer, messages: &[Witness]) -> Witness {
    let zero = TurboComposer::constant_zero();
    let mut state = [zero; WIDTH];

    let l = messages.len();
    let m = l / (WIDTH - 1);
    let n = m * (WIDTH - 1);
    let last_iteration = if l == n { m - 1 } else { l / (WIDTH - 1) };

    messages
        .chunks(WIDTH - 1)
        .enumerate()
        .for_each(|(i, chunk)| {
            state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                let constraint = Constraint::new().left(1).a(*s).right(1).b(*c);

                *s = composer.gate_add(constraint);
            });

            if i == last_iteration && chunk.len() < WIDTH - 1 {
                let constraint = Constraint::new()
                    .left(1)
                    .a(state[chunk.len() + 1])
                    .constant(1);

                state[chunk.len() + 1] = composer.gate_add(constraint);
            } else if i == last_iteration {
                GadgetStrategy::gadget(composer, &mut state);

                let constraint =
                    Constraint::new().left(1).a(state[1]).constant(1);

                state[1] = composer.gate_add(constraint);
            }

            GadgetStrategy::gadget(composer, &mut state);
        });

    state[1]
}
