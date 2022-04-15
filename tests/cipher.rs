// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::ops::Mul;
use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{
    dhke, JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR,
    GENERATOR_EXTENDED,
};
use dusk_plonk::error::Error as PlonkError;
use dusk_poseidon::cipher::{self, PoseidonCipher};
use dusk_poseidon::Error;
use rand_core::{OsRng, RngCore};

use dusk_plonk::prelude::*;

fn gen() -> (
    [BlsScalar; PoseidonCipher::capacity()],
    JubJubAffine,
    BlsScalar,
) {
    let mut rng = OsRng;
    let mut message = [BlsScalar::zero(); PoseidonCipher::capacity()];
    message
        .iter_mut()
        .for_each(|m| *m = BlsScalar::random(&mut rng));

    let mut secret = [0u8; 64];
    rng.fill_bytes(&mut secret);
    let secret = JubJubScalar::from_bytes_wide(&secret);
    let secret = GENERATOR.to_niels().mul(&secret).into();

    let nonce = BlsScalar::random(&mut OsRng);

    (message, secret, nonce)
}

#[test]
fn sanity() {
    // The secret is always a pair with nonce, so the message capacity should be
    // at least 2
    assert!(PoseidonCipher::capacity() > 1);

    // The cipher size only makes sense to be `capacity + 1`
    assert_eq!(
        PoseidonCipher::cipher_size(),
        PoseidonCipher::capacity() + 1
    );

    // The hades permutation cannot be performed if the cipher is bigger than
    // hades width
    assert!(dusk_hades::WIDTH >= PoseidonCipher::cipher_size());
}

#[test]
fn encrypt() -> Result<(), Error> {
    let (message, secret, nonce) = gen();

    let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
    let decrypt = cipher.decrypt(&secret, &nonce)?;

    assert_eq!(message, decrypt);

    Ok(())
}

#[test]
fn single_bit() -> Result<(), Error> {
    let (_, secret, nonce) = gen();
    let message = BlsScalar::random(&mut OsRng);

    let cipher = PoseidonCipher::encrypt(&[message], &secret, &nonce);
    let decrypt = cipher.decrypt(&secret, &nonce)?;

    assert_eq!(message, decrypt[0]);

    Ok(())
}

#[test]
fn overflow() -> Result<(), Error> {
    let (_, secret, nonce) = gen();
    let message =
        [BlsScalar::random(&mut OsRng); PoseidonCipher::capacity() + 1];

    let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
    let decrypt = cipher.decrypt(&secret, &nonce)?;

    assert_eq!(message[0..PoseidonCipher::capacity()], decrypt);

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
fn bytes() -> Result<(), Error> {
    let (message, secret, nonce) = gen();

    let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);

    let bytes = cipher.to_bytes();
    let restored_cipher = PoseidonCipher::from_bytes(&bytes).unwrap();

    assert_eq!(cipher, restored_cipher);

    let decrypt = restored_cipher.decrypt(&secret, &nonce)?;

    assert_eq!(message, decrypt);

    Ok(())
}

#[derive(Debug)]
pub struct TestCipherCircuit<'a> {
    secret: JubJubScalar,
    public: JubJubExtended,
    nonce: BlsScalar,
    message: &'a [BlsScalar],
    cipher: &'a [BlsScalar],
}

impl<'a> TestCipherCircuit<'a> {
    pub const fn new(
        secret: JubJubScalar,
        public: JubJubExtended,
        nonce: BlsScalar,
        message: &'a [BlsScalar],
        cipher: &'a [BlsScalar],
    ) -> Self {
        Self {
            secret,
            public,
            nonce,
            message,
            cipher,
        }
    }
}

impl<'a> Default for TestCipherCircuit<'a> {
    fn default() -> Self {
        let secret = Default::default();
        let nonce = Default::default();
        let message = Default::default();

        const MESSAGE: [BlsScalar; PoseidonCipher::capacity()] =
            [BlsScalar::zero(); PoseidonCipher::capacity()];
        const CIPHER: [BlsScalar; PoseidonCipher::cipher_size()] =
            [BlsScalar::zero(); PoseidonCipher::cipher_size()];

        Self::new(secret, nonce, message, &MESSAGE, &CIPHER)
    }
}

impl<'a> Circuit for TestCipherCircuit<'a> {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        let zero = TurboComposer::constant_zero();
        let nonce = composer.append_witness(self.nonce);

        let secret = composer.append_witness(self.secret);
        let public = composer.append_point(self.public);

        let shared = composer.component_mul_point(secret, public);

        let mut message_circuit = [zero; PoseidonCipher::capacity()];

        self.message
            .iter()
            .zip(message_circuit.iter_mut())
            .for_each(|(m, v)| {
                *v = composer.append_witness(*m);
            });

        let cipher_gadget =
            cipher::encrypt(composer, &shared, nonce, &message_circuit);

        self.cipher
            .iter()
            .zip(cipher_gadget.iter())
            .for_each(|(c, g)| {
                let x = composer.append_witness(*c);
                composer.assert_equal(x, *g);
            });

        let message_gadget =
            cipher::decrypt(composer, &shared, nonce, &cipher_gadget);

        self.message
            .iter()
            .zip(message_gadget.iter())
            .for_each(|(m, g)| {
                let x = composer.append_witness(*m);
                composer.assert_equal(x, *g);
            });

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << 15
    }
}

#[test]
fn gadget() -> Result<(), PlonkError> {
    // Generate a secret and a public key for Bob
    let bob_secret = JubJubScalar::random(&mut OsRng);

    // Generate a secret and a public key for Alice
    let alice_secret = JubJubScalar::random(&mut OsRng);
    let alice_public = GENERATOR_EXTENDED * alice_secret;

    // Generate a shared secret
    let shared_secret = dhke(&bob_secret, &alice_public);

    // Generate a secret message
    let a = BlsScalar::random(&mut OsRng);
    let b = BlsScalar::random(&mut OsRng);
    let message = [a, b, a, b, a, b];

    // Perform the encryption
    let nonce = BlsScalar::random(&mut OsRng);
    let cipher = PoseidonCipher::encrypt(&message, &shared_secret, &nonce);

    let label = b"poseidon-cipher";
    let size = 15;

    let pp = PublicParameters::setup(1 << size, &mut OsRng)?;
    let (pk, vd) = TestCipherCircuit::default().compile(&pp)?;

    let proof = TestCipherCircuit::new(
        bob_secret,
        alice_public,
        nonce,
        &message,
        cipher.cipher(),
    )
    .prove(&pp, &pk, label)?;

    TestCipherCircuit::verify(&pp, &vd, &proof, &[], label)?;

    Ok(())
}
