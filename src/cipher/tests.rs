// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::{PoseidonCipher, CIPHER_SIZE, MESSAGE_CAPACITY};
use anyhow::Result;
use dusk_plonk::jubjub::{
    JubJubAffine as AffinePoint, JubJubScalar as Fr, GENERATOR,
};
use dusk_plonk::prelude::*;
use hades252::WIDTH;
use rand::RngCore;
use std::ops::Mul;

fn gen() -> ([BlsScalar; MESSAGE_CAPACITY], AffinePoint, BlsScalar) {
    let mut rng = rand::thread_rng();

    let mut message = [BlsScalar::zero(); MESSAGE_CAPACITY];
    message
        .iter_mut()
        .for_each(|m| *m = BlsScalar::random(&mut rng));

    let mut secret = [0u8; 64];
    rng.fill_bytes(&mut secret);
    let secret = Fr::from_bytes_wide(&secret);
    let secret = GENERATOR.to_niels().mul(&secret).into();

    let nonce = BlsScalar::random(&mut rng);

    (message, secret, nonce)
}

#[test]
fn sanity() {
    // The secret is always a pair with nonce, so the message capacity should be at least 2
    assert!(MESSAGE_CAPACITY > 1);

    // The cipher size only makes sense to be `capacity + 1`
    assert_eq!(CIPHER_SIZE, MESSAGE_CAPACITY + 1);

    // The hades permutation cannot be performed if the cipher is bigger than hades width
    assert!(WIDTH >= CIPHER_SIZE);
}

#[test]
fn encrypt() -> Result<()> {
    let (message, secret, nonce) = gen();

    let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
    let decrypt = cipher.decrypt(&secret, &nonce)?;

    assert_eq!(message, decrypt);

    Ok(())
}

#[test]
fn single_bit() -> Result<()> {
    let (_, secret, nonce) = gen();
    let message = BlsScalar::random(&mut rand::thread_rng());

    let cipher = PoseidonCipher::encrypt(&[message], &secret, &nonce);
    let decrypt = cipher.decrypt(&secret, &nonce)?;

    assert_eq!(message, decrypt[0]);

    Ok(())
}

#[test]
fn overflow() -> Result<()> {
    let (_, secret, nonce) = gen();
    let message =
        [BlsScalar::random(&mut rand::thread_rng()); MESSAGE_CAPACITY + 1];

    let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
    let decrypt = cipher.decrypt(&secret, &nonce)?;

    assert_eq!(message[0..MESSAGE_CAPACITY], decrypt);

    Ok(())
}

#[test]
fn wrong_key_fail() {
    let (message, secret, nonce) = gen();
    let (_, wrong_secret, _) = gen();

    let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
    assert!(cipher.decrypt(&wrong_secret, &nonce).is_err());
}

#[test]
fn bytes() -> Result<()> {
    let (message, secret, nonce) = gen();

    let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);

    let bytes = cipher.to_bytes();
    let restored_cipher = PoseidonCipher::from_bytes(&bytes).unwrap();

    assert_eq!(cipher, restored_cipher);

    let decrypt = restored_cipher.decrypt(&secret, &nonce)?;

    assert_eq!(message, decrypt);

    Ok(())
}
