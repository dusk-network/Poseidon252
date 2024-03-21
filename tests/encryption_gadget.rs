// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "encryption")]
#![cfg(feature = "zk")]

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_EXTENDED};
use dusk_plonk::prelude::Error as PlonkError;
use dusk_plonk::prelude::*;
use dusk_poseidon::{decrypt_gadget, encrypt, encrypt_gadget};
use ff::Field;
use once_cell::sync::Lazy;
use rand::rngs::StdRng;
use rand::SeedableRng;

static PUB_PARAMS: Lazy<PublicParameters> = Lazy::new(|| {
    let mut rng = StdRng::seed_from_u64(0xfab);

    const CAPACITY: usize = 13;
    PublicParameters::setup(1 << CAPACITY, &mut rng)
        .expect("Setup of public params should pass")
});
static LABEL: &[u8] = b"hash-gadget-tester";

#[derive(Debug)]
struct EncryptionCircuit<const L: usize> {
    pub message: [BlsScalar; L],
    pub cipher: Vec<BlsScalar>,
    pub shared_secret: JubJubAffine,
    pub nonce: BlsScalar,
}

impl<const L: usize> EncryptionCircuit<L> {
    pub fn random(rng: &mut StdRng) -> Self {
        let mut message = [BlsScalar::zero(); L];
        message
            .iter_mut()
            .for_each(|s| *s = BlsScalar::random(&mut *rng));
        let shared_secret =
            GENERATOR_EXTENDED * &JubJubScalar::random(&mut *rng);
        let nonce = BlsScalar::random(&mut *rng);
        let cipher = encrypt(&message, &shared_secret.into(), &nonce)
            .expect("encryption should pass");
        assert_eq!(message.len() + 1, cipher.len());

        Self {
            message,
            cipher,
            shared_secret: shared_secret.into(),
            nonce,
        }
    }
}

impl<const L: usize> Default for EncryptionCircuit<L> {
    fn default() -> Self {
        let message = [BlsScalar::zero(); L];
        let mut cipher = message.to_vec();
        cipher.push(BlsScalar::zero());
        let shared_secret = JubJubAffine::identity();
        let nonce = BlsScalar::zero();

        Self {
            message,
            cipher,
            shared_secret,
            nonce,
        }
    }
}

impl<const L: usize> Circuit for EncryptionCircuit<L> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        // append all variables to the circuit
        let mut message_wit = [Composer::ZERO; L];
        message_wit
            .iter_mut()
            .zip(self.message)
            .for_each(|(w, m)| *w = composer.append_witness(m));
        let secret_wit = composer.append_point(self.shared_secret);
        let nonce_wit = composer.append_witness(self.nonce);

        // encrypt the message with the gadget
        let cipher_result =
            encrypt_gadget(composer, &message_wit, &secret_wit, &nonce_wit)
                .expect("encryption should pass");

        // ensure that the resulting cipher-text is correct
        assert_eq!(cipher_result.len(), self.cipher.len());
        cipher_result
            .iter()
            .zip(&self.cipher)
            .for_each(|(r, c)| composer.assert_equal_constant(*r, 0, Some(*c)));

        // decrypt the cipher result with the gadget
        let message_result =
            decrypt_gadget(composer, &cipher_result, &secret_wit, &nonce_wit)
                .expect("decryption should pass");

        // assert that the decrypted message is the same as in the beginning
        assert_eq!(message_result.len(), L);
        message_result
            .iter()
            .zip(message_wit)
            .for_each(|(r, w)| composer.assert_equal(*r, w));

        Ok(())
    }
}

#[test]
fn encrypt_decrypt() -> Result<(), PlonkError> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    const MESSAGE_LEN: usize = 4;

    let (prover, verifier) = Compiler::compile::<EncryptionCircuit<MESSAGE_LEN>>(
        &PUB_PARAMS,
        LABEL,
    )?;

    let circuit: EncryptionCircuit<MESSAGE_LEN> =
        EncryptionCircuit::random(&mut rng);

    let (proof, _public_inputs) = prover.prove(&mut rng, &circuit)?;

    let public_inputs = &circuit.cipher;
    verifier.verify(&proof, public_inputs)
}

#[test]
fn incorrect_shared_secret_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    const MESSAGE_LEN: usize = 5;

    let (prover, _verifier) = Compiler::compile::<
        EncryptionCircuit<MESSAGE_LEN>,
    >(&PUB_PARAMS, LABEL)?;

    let mut circuit: EncryptionCircuit<MESSAGE_LEN> =
        EncryptionCircuit::random(&mut rng);

    let wrong_shared_secret =
        GENERATOR_EXTENDED * &JubJubScalar::random(&mut rng);
    circuit.shared_secret = wrong_shared_secret.into();

    assert!(prover.prove(&mut rng, &circuit).is_err());

    Ok(())
}

#[test]
fn incorrect_nonce_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    const MESSAGE_LEN: usize = 6;

    let (prover, _verifier) = Compiler::compile::<
        EncryptionCircuit<MESSAGE_LEN>,
    >(&PUB_PARAMS, LABEL)?;

    let mut circuit: EncryptionCircuit<MESSAGE_LEN> =
        EncryptionCircuit::random(&mut rng);

    let wrong_nonce = BlsScalar::random(&mut rng);
    circuit.nonce = wrong_nonce;

    assert!(prover.prove(&mut rng, &circuit).is_err());

    Ok(())
}

#[test]
fn incorrect_cipher_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    const MESSAGE_LEN: usize = 7;

    let (prover, _verifier) = Compiler::compile::<
        EncryptionCircuit<MESSAGE_LEN>,
    >(&PUB_PARAMS, LABEL)?;

    let mut circuit: EncryptionCircuit<MESSAGE_LEN> =
        EncryptionCircuit::random(&mut rng);

    let mut wrong_cipher = circuit.cipher.clone();
    wrong_cipher[2] = BlsScalar::random(&mut rng);
    circuit.cipher = wrong_cipher;

    assert!(prover.prove(&mut rng, &circuit).is_err());

    Ok(())
}

#[test]
fn incorrect_public_input_fails() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    const MESSAGE_LEN: usize = 8;

    let (prover, verifier) = Compiler::compile::<EncryptionCircuit<MESSAGE_LEN>>(
        &PUB_PARAMS,
        LABEL,
    )?;

    let circuit: EncryptionCircuit<MESSAGE_LEN> =
        EncryptionCircuit::random(&mut rng);

    let (proof, _public_inputs) = prover.prove(&mut rng, &circuit)?;

    let mut wrong_cipher = circuit.cipher.clone();
    wrong_cipher[MESSAGE_LEN] = BlsScalar::random(&mut rng);

    assert!(verifier.verify(&proof, &wrong_cipher).is_err());

    Ok(())
}
