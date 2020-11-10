// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "std")]
use super::{PoseidonCipher, CIPHER_SIZE, MESSAGE_CAPACITY};
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::prelude::*;
use hades252::{GadgetStrategy, Strategy};

/// Given a shared secret calculated using any key protocol compatible with bls and jubjub, perform
/// the encryption of the message.
///
/// The returned set of variables is the cipher text
pub fn poseidon_cipher_encrypt(
    composer: &mut StandardComposer,
    shared_secret: &Point,
    nonce: Variable,
    message: &[Variable],
) -> [Variable; CIPHER_SIZE] {
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());

    let ks0 = *shared_secret.x();
    let ks1 = *shared_secret.y();

    let mut cipher = [zero; CIPHER_SIZE];
    let mut state =
        PoseidonCipher::initial_state_circuit(composer, ks0, ks1, nonce);

    GadgetStrategy::new(composer).perm(&mut state);

    (0..MESSAGE_CAPACITY).for_each(|i| {
        let x = if i < message.len() { message[i] } else { zero };

        state[i + 1] = composer.add(
            (BlsScalar::one(), state[i + 1]),
            (BlsScalar::one(), x),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        cipher[i] = state[i + 1];
    });

    GadgetStrategy::new(composer).perm(&mut state);
    cipher[MESSAGE_CAPACITY] = state[1];

    cipher
}

/// Given a shared secret calculated using any key protocol compatible with bls and jubjub, perform
/// the decryption of the cipher.
///
/// The returned set of variables is the original message
pub fn poseidon_cipher_decrypt(
    composer: &mut StandardComposer,
    shared_secret: &Point,
    nonce: Variable,
    cipher: &[Variable],
) -> [Variable; MESSAGE_CAPACITY] {
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());

    let ks0 = *shared_secret.x();
    let ks1 = *shared_secret.y();

    let mut message = [zero; MESSAGE_CAPACITY];
    let mut state =
        PoseidonCipher::initial_state_circuit(composer, ks0, ks1, nonce);

    GadgetStrategy::new(composer).perm(&mut state);

    (0..MESSAGE_CAPACITY).for_each(|i| {
        message[i] = composer.add(
            (BlsScalar::one(), cipher[i]),
            (-BlsScalar::one(), state[i + 1]),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        state[i + 1] = cipher[i];
    });

    GadgetStrategy::new(composer).perm(&mut state);

    composer.assert_equal(cipher[MESSAGE_CAPACITY], state[1]);

    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use dusk_plonk::constraint_system::ecc::scalar_mul::variable_base::variable_base_scalar_mul;
    use dusk_plonk::jubjub::{dhke, ExtendedPoint, GENERATOR_EXTENDED};

    #[test]
    fn gadget() -> Result<()> {
        let mut rng = rand::thread_rng();

        // Generate a secret and a public key for Bob
        let bob_secret = JubJubScalar::random(&mut rng);

        // Generate a secret and a public key for Alice
        let alice_secret = JubJubScalar::random(&mut rng);
        let alice_public = GENERATOR_EXTENDED * &alice_secret;

        // Generate a shared secret
        let shared_secret = dhke(&bob_secret, &alice_public);

        // Generate a secret message
        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);
        let message = [a, b];

        // Perform the encryption
        let nonce = BlsScalar::random(&mut rng);
        let cipher = PoseidonCipher::encrypt(&message, &shared_secret, &nonce);

        let size = 14;
        let pp = PublicParameters::setup(1 << size, &mut rng)?;
        let (ck, vk) = pp.trim(1 << size)?;

        let label = b"poseidon-cipher";

        let circuit = |composer: &mut StandardComposer,
                       secret: JubJubScalar,
                       public: ExtendedPoint,
                       nonce: BlsScalar,
                       message: &[BlsScalar],
                       cipher: &[BlsScalar]| {
            let zero =
                composer.add_witness_to_circuit_description(BlsScalar::zero());
            let nonce = composer.add_input(nonce);

            let secret = composer.add_input((secret).into());
            let public = Point::from_private_affine(composer, public.into());

            let shared = variable_base_scalar_mul(composer, secret, public);

            let mut message_circuit = [zero; MESSAGE_CAPACITY];
            message.iter().zip(message_circuit.iter_mut()).for_each(
                |(m, v)| {
                    *v = composer.add_input(*m);
                },
            );

            let cipher_gadget = poseidon_cipher_encrypt(
                composer,
                shared.point(),
                nonce,
                &message_circuit,
            );

            cipher.iter().zip(cipher_gadget.iter()).for_each(|(c, g)| {
                let x = composer.add_input(*c);
                composer.assert_equal(x, *g);
            });

            let message_gadget = poseidon_cipher_decrypt(
                composer,
                shared.point(),
                nonce,
                &cipher_gadget,
            );

            message
                .iter()
                .zip(message_gadget.iter())
                .for_each(|(m, g)| {
                    let x = composer.add_input(*m);
                    composer.assert_equal(x, *g);
                });
        };

        let mut prover = Prover::new(label);
        circuit(
            prover.mut_cs(),
            bob_secret,
            alice_public,
            nonce,
            &message,
            cipher.cipher(),
        );
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Everything was performed privately on this encryption
        // There must be no public information
        prover
            .mut_cs()
            .public_inputs
            .iter()
            .try_for_each(|p| {
                if p == &BlsScalar::zero() {
                    Ok(())
                } else {
                    Err("PI is not zero")
                }
            })
            .unwrap();

        let mut verifier = Verifier::new(label);

        circuit(
            verifier.mut_cs(),
            JubJubScalar::zero(),
            GENERATOR_EXTENDED,
            nonce,
            &[BlsScalar::zero(); MESSAGE_CAPACITY],
            cipher.cipher(),
        );
        verifier.preprocess(&ck)?;

        assert!(verifier.verify(&proof, &vk, &vec![]).is_ok());

        Ok(())
    }
}
