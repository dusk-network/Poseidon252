// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "zk")]
pub(crate) mod gadget;

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubAffine;

use crate::hades::ScalarPermutation;
use crate::{Domain, Error};

/// This function encrypts a given message with a shared secret point on the
/// jubjub-curve and a bls-scalar nonce using the poseidon hash function.
///
/// The shared secret is expected to be a valid point on the jubjub-curve.
///
/// The cipher-text will always yield exactly one element more than the message.
pub fn encrypt(
    message: impl AsRef<[BlsScalar]>,
    shared_secret: &JubJubAffine,
    nonce: &BlsScalar,
) -> Result<Vec<BlsScalar>, Error> {
    Ok(dusk_safe::encrypt(
        ScalarPermutation::new(),
        Domain::Encryption,
        message,
        &[shared_secret.get_u(), shared_secret.get_v()],
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
pub fn decrypt(
    cipher: impl AsRef<[BlsScalar]>,
    shared_secret: &JubJubAffine,
    nonce: &BlsScalar,
) -> Result<Vec<BlsScalar>, Error> {
    Ok(dusk_safe::decrypt(
        ScalarPermutation::new(),
        Domain::Encryption,
        cipher,
        &[shared_secret.get_u(), shared_secret.get_v()],
        nonce,
    )?)
}
