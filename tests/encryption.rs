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

// Generated through the public encrypt API in release mode from
// dusk-poseidon v0.42.0-rc.0 at 3346c5a. A mismatch is a compatibility break,
// not a reason to regenerate these expected values.
#[test]
fn public_encryption_known_answer_vector() -> Result<(), Error> {
    let message = [
        BlsScalar::from(1u64),
        BlsScalar::from(2u64),
        BlsScalar::from(3u64),
    ];
    let shared_secret =
        JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::from(42u64));
    let nonce = BlsScalar::from(4u64);
    let ciphertext = [
        [
            0xe1, 0x4b, 0x48, 0x1a, 0xdf, 0xb0, 0xd5, 0x1d, 0x85, 0xa4, 0x4c,
            0xd9, 0x78, 0xac, 0x61, 0x60, 0x71, 0x96, 0x52, 0x65, 0x4f, 0x01,
            0x8e, 0x84, 0x5e, 0x9d, 0xa0, 0xf7, 0x15, 0xe0, 0x5f, 0x73,
        ],
        [
            0x4e, 0x67, 0x94, 0xeb, 0xa0, 0xcc, 0x43, 0x63, 0xb1, 0x09, 0xbd,
            0x32, 0x58, 0x19, 0x04, 0x72, 0x70, 0x6a, 0x17, 0xce, 0x0e, 0x15,
            0x2c, 0xe5, 0xec, 0x30, 0x6d, 0xac, 0x2b, 0x26, 0x77, 0x31,
        ],
        [
            0xcd, 0xd1, 0x67, 0xfc, 0x93, 0x60, 0x12, 0xf7, 0x27, 0x3e, 0x0f,
            0xd4, 0x0d, 0xdb, 0xfa, 0xa7, 0x05, 0xbd, 0xb4, 0x2f, 0xe1, 0xce,
            0x2d, 0x33, 0xa1, 0x9b, 0xaf, 0xe5, 0x9d, 0x7a, 0x53, 0x05,
        ],
        [
            0x29, 0x9b, 0x41, 0x02, 0x25, 0x7e, 0x58, 0x57, 0x7b, 0x72, 0x77,
            0xf9, 0x92, 0x6f, 0x17, 0xec, 0xf1, 0x25, 0x8a, 0x15, 0xf7, 0x2b,
            0xd1, 0xdc, 0xd4, 0x91, 0xf4, 0xee, 0x21, 0x0a, 0x50, 0x40,
        ],
    ];

    assert_eq!(
        encrypt(&message, &shared_secret, &nonce)?
            .iter()
            .map(BlsScalar::to_bytes)
            .collect::<Vec<_>>(),
        ciphertext,
    );

    let ciphertext =
        ciphertext.map(|value| BlsScalar::from_bytes(&value).unwrap());
    assert_eq!(decrypt(&ciphertext, &shared_secret, &nonce)?, message);

    Ok(())
}

// Generated from unchanged dusk-poseidon at 4e30edf in release mode.
// This five-element message crosses the sponge rate of four. Treat changes
// to the frozen bytes as compatibility breaks, not a reason to regenerate.
#[test]
fn public_encryption_rate_crossing_vector() -> Result<(), Error> {
    let message = (1..=5).map(BlsScalar::from).collect::<Vec<_>>();
    let shared_secret =
        JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::from(42u64));
    let nonce = BlsScalar::from(4u64);
    let ciphertext = [
        [
            0x0a, 0xcf, 0x24, 0xf2, 0x08, 0x8a, 0x8b, 0x8c, 0xce, 0xf6, 0xbe,
            0x37, 0xd1, 0x1f, 0x2a, 0xd3, 0x21, 0x95, 0xc7, 0xb1, 0xbd, 0x8a,
            0xeb, 0xc8, 0xb3, 0xf5, 0x34, 0xc8, 0x8d, 0x16, 0xc7, 0x1d,
        ],
        [
            0x93, 0xa2, 0x81, 0x43, 0x95, 0xe9, 0x0f, 0xc0, 0x9e, 0x2e, 0x5d,
            0x30, 0x58, 0xc9, 0x0d, 0x64, 0x7c, 0x65, 0x78, 0x9e, 0x9e, 0x42,
            0x71, 0x04, 0x58, 0x7c, 0x18, 0xda, 0x9d, 0x69, 0x80, 0x17,
        ],
        [
            0x78, 0xa2, 0x30, 0xce, 0xb3, 0x44, 0x05, 0xaf, 0x40, 0xd2, 0x6a,
            0xfd, 0xa7, 0xc3, 0x0a, 0x79, 0x3b, 0x6c, 0xf3, 0x67, 0xe1, 0xe7,
            0x57, 0x5b, 0xf5, 0x83, 0x8f, 0x4e, 0x43, 0x07, 0xd4, 0x12,
        ],
        [
            0xe8, 0xef, 0x2c, 0x54, 0x6d, 0x87, 0x9b, 0x7c, 0x67, 0xb2, 0x78,
            0x67, 0xc3, 0xc2, 0x25, 0xdc, 0x14, 0xa0, 0xa2, 0x84, 0xb0, 0x98,
            0xe3, 0xb8, 0x29, 0x90, 0xca, 0xa0, 0xab, 0x09, 0x61, 0x59,
        ],
        [
            0x77, 0xcf, 0x07, 0xdb, 0x7b, 0x90, 0x9a, 0xf2, 0x2f, 0x5a, 0x71,
            0x88, 0xfa, 0x26, 0x42, 0x0e, 0x79, 0x67, 0x71, 0x5f, 0xc7, 0xf0,
            0x3a, 0x04, 0xf9, 0xb2, 0x1f, 0x42, 0x23, 0x69, 0x58, 0x18,
        ],
        [
            0x6e, 0xcf, 0x01, 0x8f, 0x70, 0xdb, 0xe6, 0x32, 0xd7, 0x1f, 0xee,
            0x3b, 0x26, 0x12, 0xf7, 0x7f, 0x57, 0x64, 0xec, 0xfd, 0x38, 0x48,
            0x89, 0xb9, 0xc8, 0x18, 0x2d, 0x97, 0xf4, 0xd6, 0x39, 0x6a,
        ],
    ];
    assert_eq!(
        encrypt(&message, &shared_secret, &nonce)?
            .iter()
            .map(BlsScalar::to_bytes)
            .collect::<Vec<_>>(),
        ciphertext,
    );
    let ciphertext =
        ciphertext.map(|value| BlsScalar::from_bytes(&value).unwrap());
    assert_eq!(decrypt(ciphertext, &shared_secret, &nonce)?, message);
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
