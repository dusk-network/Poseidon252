// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_plonk::prelude::{Composer, Witness, WitnessPoint};

use crate::hades::GadgetPermutation;
use crate::{Domain, Error};

/// This function encrypts a given message with a shared secret point on the
/// jubjub-curve and a bls-scalar nonce using the poseidon hash function.
///
/// The shared secret is expected to be a valid point on the jubjub-curve.
///
/// The cipher-text will always yield exactly one element more than the message.
pub fn encrypt_gadget(
    composer: &mut Composer,
    message: impl AsRef<[Witness]>,
    shared_secret: &WitnessPoint,
    nonce: &Witness,
) -> Result<Vec<Witness>, Error> {
    Ok(dusk_safe::encrypt(
        GadgetPermutation::new(composer),
        Domain::Encryption,
        message,
        &[*shared_secret.x(), *shared_secret.y()],
        nonce,
    )?)
}

/// This function decrypts a message from a given cipher-text with a shared
/// secret point on the jubjub-curve and a bls-scalar nonce using the poseidon
/// hash function.
///
/// The shared secret is expected to be a valid point on the jubjub-curve.
///
/// The cipher-text will always yield exactly one element more than the message.
pub fn decrypt_gadget(
    composer: &mut Composer,
    cipher: impl AsRef<[Witness]>,
    shared_secret: &WitnessPoint,
    nonce: &Witness,
) -> Result<Vec<Witness>, Error> {
    Ok(dusk_safe::decrypt(
        GadgetPermutation::new(composer),
        Domain::Encryption,
        cipher,
        &[*shared_secret.x(), *shared_secret.y()],
        nonce,
    )?)
}
