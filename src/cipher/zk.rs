// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::cipher::PoseidonCipher;
use dusk_hades::GadgetStrategy;

use dusk_plonk::prelude::*;

impl PoseidonCipher {
    /// Returns the initial state of the encryption within a composer circuit
    pub fn initial_state_circuit(
        composer: &mut TurboComposer,
        ks0: Witness,
        ks1: Witness,
        nonce: Witness,
    ) -> [Witness; dusk_hades::WIDTH] {
        let domain = BlsScalar::from_raw([0x100000000u64, 0, 0, 0]);
        let domain = composer.append_constant(domain);

        let length =
            BlsScalar::from_raw([PoseidonCipher::capacity() as u64, 0, 0, 0]);
        let length = composer.append_constant(length);

        [domain, length, ks0, ks1, nonce]
    }
}

/// Given a shared secret calculated using any key protocol compatible with bls and jubjub, perform
/// the encryption of the message.
///
/// The returned set of variables is the cipher text
pub fn encrypt(
    composer: &mut TurboComposer,
    shared_secret: &WitnessPoint,
    nonce: Witness,
    message: &[Witness],
) -> [Witness; PoseidonCipher::cipher_size()] {
    let zero = TurboComposer::constant_zero();

    let ks0 = *shared_secret.x();
    let ks1 = *shared_secret.y();

    let mut cipher = [zero; PoseidonCipher::cipher_size()];

    let mut state =
        PoseidonCipher::initial_state_circuit(composer, ks0, ks1, nonce);

    let count = (PoseidonCipher::capacity() + 3) / 4;

    (0..count).for_each(|i| {
        GadgetStrategy::gadget(composer, &mut state);

        (0..4).for_each(|j| {
            if 4*i + j < PoseidonCipher::capacity() {
                let x = if 4*i + j < message.len() { message[4*i + j] } else { zero };

                let constraint =
                    Constraint::new().left(1).a(state[j + 1]).right(1).b(x);

                state[j + 1] = composer.gate_add(constraint);

                cipher[4*i + j] = state[j + 1];
            }
        });
    });

    GadgetStrategy::gadget(composer, &mut state);
    cipher[PoseidonCipher::capacity()] = state[1];

    cipher
}

/// Given a shared secret calculated using any key protocol compatible with bls and jubjub, perform
/// the decryption of the cipher.
///
/// The returned set of variables is the original message
pub fn decrypt(
    composer: &mut TurboComposer,
    shared_secret: &WitnessPoint,
    nonce: Witness,
    cipher: &[Witness],
) -> [Witness; PoseidonCipher::capacity()] {
    let zero = TurboComposer::constant_zero();

    let ks0 = *shared_secret.x();
    let ks1 = *shared_secret.y();

    let mut message = [zero; PoseidonCipher::capacity()];
    let mut state =
        PoseidonCipher::initial_state_circuit(composer, ks0, ks1, nonce);

    let count = (PoseidonCipher::capacity() + 3) / 4;

    (0..count).for_each(|i| {
        GadgetStrategy::gadget(composer, &mut state);

        (0..4).for_each(|j| {
            if 4 * i + j < PoseidonCipher::capacity() {
                let constraint = Constraint::new()
                    .left(1)
                    .a(cipher[4 * i + j])
                    .right(-BlsScalar::one())
                    .b(state[j + 1]);

                message[4 * i + j] = composer.gate_add(constraint);

                state[j + 1] = cipher[4 * i + j];
            }
        });
    });

    GadgetStrategy::gadget(composer, &mut state);

    composer.assert_equal(cipher[PoseidonCipher::capacity()], state[1]);

    message
}
