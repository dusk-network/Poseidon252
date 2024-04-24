// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Encryption using the poseidon hash function:
//!
//! ## Example
//!
//! ```rust
//! #![cfg(feature = "encryption")]
//!
//! use dusk_bls12_381::BlsScalar;
//! use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, dhke};
//! use dusk_poseidon::{decrypt, encrypt, Error};
//! use ff::Field;
//! use rand::rngs::StdRng;
//! use rand::SeedableRng;
//!
//! // generate the keys and nonce needed for the encryption
//! let mut rng = StdRng::seed_from_u64(0x42424242);
//! let alice_secret = JubJubScalar::random(&mut rng);
//! let alice_public = GENERATOR_EXTENDED * &alice_secret;
//! let bob_secret = JubJubScalar::random(&mut rng);
//! let bob_public = GENERATOR_EXTENDED * &bob_secret;
//! let nonce = BlsScalar::random(&mut rng);
//!
//! // Alice encrypts a message of 3 BlsScalar using Diffie-Hellman key exchange
//! // with Bob's public key
//! let message = vec![BlsScalar::from(10), BlsScalar::from(20), BlsScalar::from(30)];
//! let shared_secret = dhke(&alice_secret, &bob_public);
//! let cipher = encrypt(&message, &shared_secret, &nonce)
//!     .expect("Encryption should pass");
//!
//! // Bob decrypts the cipher using Diffie-Hellman key exchange with Alice's
//! // public key
//! let shared_secret = dhke(&bob_secret, &alice_public);
//! let decrypted_message = decrypt(&cipher, &shared_secret, &nonce)
//!     .expect("Decryption should pass");
//!
//! assert_eq!(decrypted_message, message);
//! ```

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
