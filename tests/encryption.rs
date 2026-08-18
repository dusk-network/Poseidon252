// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "encryption")]

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubAffine, JubJubScalar};
use dusk_poseidon::{Error, decrypt, encrypt};
use ff::Field;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn encryption_variables(
    rng: &mut StdRng,
    message_len: usize,
) -> (Vec<BlsScalar>, JubJubAffine, BlsScalar) {
    let mut message = Vec::with_capacity(message_len);
    for _ in 0..message_len {
        message.push(BlsScalar::random(&mut *rng));
    }
    let shared_secret = GENERATOR_EXTENDED * &JubJubScalar::random(&mut *rng);
    let nonce = BlsScalar::random(&mut *rng);

    (message, shared_secret.into(), nonce)
}

#[test]
fn encrypt_decrypt() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let message_len = 42usize;

    let (message, shared_secret, nonce) =
        encryption_variables(&mut rng, message_len);

    let cipher = encrypt(&message, &shared_secret, &nonce)?;

    let decrypted_message = decrypt(&cipher, &shared_secret, &nonce)?;

    assert_eq!(decrypted_message, message);

    Ok(())
}

#[test]
fn non_prime_order_shared_secrets_fail() {
    let message = [BlsScalar::from(42)];
    let cipher = [BlsScalar::from(1), BlsScalar::from(2)];
    let nonce = BlsScalar::from(3);
    let identity = JubJubAffine::identity();
    let low_order =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), -BlsScalar::one());
    let off_curve =
        JubJubAffine::from_raw_unchecked(BlsScalar::zero(), BlsScalar::zero());
    let mixed_order = JubJubAffine::from(GENERATOR_EXTENDED + low_order);

    assert!(bool::from(identity.is_on_curve()));
    assert!(bool::from(identity.is_torsion_free()));
    assert!(bool::from(identity.is_identity()));
    assert!(bool::from(low_order.is_on_curve()));
    assert!(!bool::from(low_order.is_torsion_free()));
    assert!(!bool::from(low_order.is_identity()));
    assert!(!bool::from(off_curve.is_on_curve()));
    assert!(bool::from(mixed_order.is_on_curve()));
    assert!(!bool::from(mixed_order.is_torsion_free()));
    assert!(!bool::from(mixed_order.is_identity()));
    assert!(!bool::from(mixed_order.is_small_order()));

    let invalid_secrets = [identity, low_order, off_curve, mixed_order];

    for shared_secret in invalid_secrets {
        assert_eq!(
            encrypt(message, &shared_secret, &nonce).unwrap_err(),
            Error::InvalidPoint
        );
        assert_eq!(
            decrypt(cipher, &shared_secret, &nonce).unwrap_err(),
            Error::InvalidPoint
        );
    }
}

#[test]
fn incorrect_shared_secret_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let message_len = 21usize;

    let (message, shared_secret, nonce) =
        encryption_variables(&mut rng, message_len);

    let cipher = encrypt(&message, &shared_secret, &nonce)?;

    let wrong_shared_secret =
        GENERATOR_EXTENDED * &JubJubScalar::random(&mut rng);
    assert_ne!(shared_secret, wrong_shared_secret.into());

    assert_eq!(
        decrypt(&cipher, &wrong_shared_secret.into(), &nonce,).unwrap_err(),
        Error::DecryptionFailed
    );

    Ok(())
}

#[test]
fn incorrect_nonce_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let message_len = 21usize;

    let (message, shared_secret, nonce) =
        encryption_variables(&mut rng, message_len);

    let cipher = encrypt(&message, &shared_secret, &nonce)?;

    let wrong_nonce = BlsScalar::random(&mut rng);
    assert_ne!(nonce, wrong_nonce);

    assert_eq!(
        decrypt(&cipher, &shared_secret, &wrong_nonce,).unwrap_err(),
        Error::DecryptionFailed
    );

    Ok(())
}

#[test]
fn incorrect_cipher_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let message_len = 21usize;

    let (message, shared_secret, nonce) =
        encryption_variables(&mut rng, message_len);

    let cipher = encrypt(&message, &shared_secret, &nonce)?;

    let mut wrong_cipher = cipher.clone();
    wrong_cipher[message_len] += BlsScalar::from(42);
    assert_eq!(
        decrypt(&wrong_cipher, &shared_secret, &nonce,).unwrap_err(),
        Error::DecryptionFailed
    );

    let mut wrong_cipher = cipher.clone();
    wrong_cipher[0] += BlsScalar::from(42);
    assert_eq!(
        decrypt(&wrong_cipher, &shared_secret, &nonce,).unwrap_err(),
        Error::DecryptionFailed
    );

    Ok(())
}
