// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "encryption")]
#![cfg(feature = "zk")]

use std::sync::LazyLock;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::{Error as PlonkError, *};
use dusk_poseidon::{decrypt_gadget, encrypt, encrypt_gadget};
use ff::Field;
use rand::SeedableRng;
use rand::rngs::StdRng;

static PUB_PARAMS: LazyLock<PublicParameters> = LazyLock::new(|| {
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
        let secret_wit = composer.append_point(self.shared_secret)?;
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

#[derive(Debug)]
struct DecryptionCircuit<const L: usize> {
    pub cipher: Vec<BlsScalar>,
    pub message: [BlsScalar; L],
    pub shared_secret: JubJubAffine,
    pub nonce: BlsScalar,
}

impl<const L: usize> DecryptionCircuit<L> {
    pub fn random(rng: &mut StdRng) -> Self {
        let EncryptionCircuit {
            message,
            cipher,
            shared_secret,
            nonce,
        } = EncryptionCircuit::<L>::random(rng);

        Self {
            cipher,
            message,
            shared_secret,
            nonce,
        }
    }
}

impl<const L: usize> Default for DecryptionCircuit<L> {
    fn default() -> Self {
        Self {
            cipher: vec![BlsScalar::zero(); L + 1],
            message: [BlsScalar::zero(); L],
            shared_secret: JubJubAffine::identity(),
            nonce: BlsScalar::zero(),
        }
    }
}

impl<const L: usize> Circuit for DecryptionCircuit<L> {
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        // the cipher-text enters the circuit as private witnesses, so only the
        // gadget's own constraints can reject it
        let cipher_wit: Vec<Witness> = self
            .cipher
            .iter()
            .map(|c| composer.append_witness(*c))
            .collect();
        let secret_wit = composer.append_point(self.shared_secret)?;
        let nonce_wit = composer.append_witness(self.nonce);

        let message_result =
            decrypt_gadget(composer, &cipher_wit, &secret_wit, &nonce_wit)
                .expect("decryption should pass");

        // expose the decrypted message as public inputs
        assert_eq!(message_result.len(), L);
        message_result
            .iter()
            .zip(self.message)
            .for_each(|(r, m)| composer.assert_equal_constant(*r, 0, Some(m)));

        Ok(())
    }
}

#[test]
fn decrypt_gadget_rejects_forged_cipher_texts() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    const MESSAGE_LEN: usize = 3;

    let (prover, verifier) = Compiler::compile::<DecryptionCircuit<MESSAGE_LEN>>(
        &PUB_PARAMS,
        LABEL,
    )?;

    // the honest cipher-text decrypts in-circuit
    let honest = DecryptionCircuit::<MESSAGE_LEN>::random(&mut rng);
    let (proof, public_inputs) = prover.prove(&mut rng, &honest)?;
    assert_eq!(public_inputs, honest.message);
    verifier.verify(&proof, &public_inputs)?;

    // A forged tag leaves the decrypted message unchanged, and shifting a
    // cipher-text element shifts the decrypted message by the same amount.
    // Both forgeries keep the claimed message consistent with the
    // cipher-text, so only the in-circuit tag check can reject them.
    let mut forged_tag = DecryptionCircuit::<MESSAGE_LEN>::random(&mut rng);
    forged_tag.cipher[MESSAGE_LEN] += BlsScalar::one();

    let mut forged_element = DecryptionCircuit::<MESSAGE_LEN>::random(&mut rng);
    forged_element.cipher[1] += BlsScalar::one();
    forged_element.message[1] += BlsScalar::one();

    for forged in [forged_tag, forged_element] {
        assert_eq!(
            prover.prove(&mut rng, &forged).err(),
            Some(Error::CircuitUnsatisfied),
            "the decryption gadget must reject a cipher-text with a forged tag"
        );
    }

    Ok(())
}

/// Pins the gate counts of the encryption gadgets for a message of three
/// elements. A changed count changes the verifier key of every circuit that
/// uses the gadgets, so update these values only for an intended layout
/// change.
#[test]
fn encryption_gadget_constraint_counts() {
    let count = |decrypt: bool| {
        let mut composer = Composer::initialized();
        let input: Vec<Witness> = (0..4u64)
            .map(|i| composer.append_witness(BlsScalar::from(i)))
            .collect();
        let shared_secret = composer
            .append_point(JubJubAffine::identity())
            .expect("the identity is a valid point");
        let nonce = composer.append_witness(BlsScalar::zero());

        let gates = composer.constraints();
        if decrypt {
            let _ =
                decrypt_gadget(&mut composer, &input, &shared_secret, &nonce);
        } else {
            let _ = encrypt_gadget(
                &mut composer,
                &input[..3],
                &shared_secret,
                &nonce,
            );
        }
        composer.constraints() - gates
    };

    assert_eq!(count(false), 1310);
    assert_eq!(count(true), 1311);
}
