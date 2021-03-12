// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::cipher::PoseidonCipher;
use dusk_bls12_381::BlsScalar;
use dusk_hades::strategies::{GadgetStrategy, Strategy};
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::prelude::*;

impl PoseidonCipher {
    /// Returns the initial state of the encryption within a composer circuit
    pub fn initial_state_circuit(
        composer: &mut StandardComposer,
        ks0: Variable,
        ks1: Variable,
        nonce: Variable,
    ) -> [Variable; dusk_hades::WIDTH] {
        let domain = BlsScalar::from_raw([0x100000000u64, 0, 0, 0]);
        let domain = composer.add_witness_to_circuit_description(domain);

        let length =
            BlsScalar::from_raw([PoseidonCipher::capacity() as u64, 0, 0, 0]);
        let length = composer.add_witness_to_circuit_description(length);

        [domain, length, ks0, ks1, nonce]
    }
}

/// Given a shared secret calculated using any key protocol compatible with bls and jubjub, perform
/// the encryption of the message.
///
/// The returned set of variables is the cipher text
pub fn encrypt(
    composer: &mut StandardComposer,
    shared_secret: &Point,
    nonce: Variable,
    message: &[Variable],
) -> [Variable; PoseidonCipher::cipher_size()] {
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());

    let ks0 = *shared_secret.x();
    let ks1 = *shared_secret.y();

    let mut cipher = [zero; PoseidonCipher::cipher_size()];
    let mut state =
        PoseidonCipher::initial_state_circuit(composer, ks0, ks1, nonce);

    GadgetStrategy::new(composer).perm(&mut state);

    (0..PoseidonCipher::capacity()).for_each(|i| {
        let x = if i < message.len() { message[i] } else { zero };

        state[i + 1] = composer.add(
            (BlsScalar::one(), state[i + 1]),
            (BlsScalar::one(), x),
            BlsScalar::zero(),
            None,
        );

        cipher[i] = state[i + 1];
    });

    GadgetStrategy::new(composer).perm(&mut state);
    cipher[PoseidonCipher::capacity()] = state[1];

    cipher
}

/// Given a shared secret calculated using any key protocol compatible with bls and jubjub, perform
/// the decryption of the cipher.
///
/// The returned set of variables is the original message
pub fn decrypt(
    composer: &mut StandardComposer,
    shared_secret: &Point,
    nonce: Variable,
    cipher: &[Variable],
) -> [Variable; PoseidonCipher::capacity()] {
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());

    let ks0 = *shared_secret.x();
    let ks1 = *shared_secret.y();

    let mut message = [zero; PoseidonCipher::capacity()];
    let mut state =
        PoseidonCipher::initial_state_circuit(composer, ks0, ks1, nonce);

    GadgetStrategy::new(composer).perm(&mut state);

    (0..PoseidonCipher::capacity()).for_each(|i| {
        message[i] = composer.add(
            (BlsScalar::one(), cipher[i]),
            (-BlsScalar::one(), state[i + 1]),
            BlsScalar::zero(),
            None,
        );

        state[i + 1] = cipher[i];
    });

    GadgetStrategy::new(composer).perm(&mut state);

    composer.assert_equal(cipher[PoseidonCipher::capacity()], state[1]);

    message
}

#[cfg(test)]
mod tests {
    use crate::cipher::{decrypt, encrypt, PoseidonCipher};
    use anyhow::Result;
    use dusk_bls12_381::BlsScalar;
    use dusk_jubjub::{dhke, JubJubExtended, GENERATOR_EXTENDED};
    use dusk_plonk::constraint_system::ecc::scalar_mul::variable_base::variable_base_scalar_mul;
    use dusk_plonk::constraint_system::ecc::Point;
    use dusk_plonk::prelude::*;

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

        let size = 13;
        let pp = PublicParameters::setup(1 << size, &mut rng)?;
        let (ck, vk) = pp.trim(1 << size)?;

        let label = b"poseidon-cipher";

        let circuit = |composer: &mut StandardComposer,
                       secret: JubJubScalar,
                       public: JubJubExtended,
                       nonce: BlsScalar,
                       message: &[BlsScalar],
                       cipher: &[BlsScalar]| {
            let zero =
                composer.add_witness_to_circuit_description(BlsScalar::zero());
            let nonce = composer.add_input(nonce);

            let secret = composer.add_input((secret).into());
            let public = Point::from_private_affine(composer, public.into());

            let shared = variable_base_scalar_mul(composer, secret, public);

            let mut message_circuit = [zero; PoseidonCipher::capacity()];
            message.iter().zip(message_circuit.iter_mut()).for_each(
                |(m, v)| {
                    *v = composer.add_input(*m);
                },
            );

            let cipher_gadget =
                encrypt(composer, shared.point(), nonce, &message_circuit);

            cipher.iter().zip(cipher_gadget.iter()).for_each(|(c, g)| {
                let x = composer.add_input(*c);
                composer.assert_equal(x, *g);
            });

            let message_gadget =
                decrypt(composer, shared.point(), nonce, &cipher_gadget);

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

        let mut verifier = Verifier::new(label);

        circuit(
            verifier.mut_cs(),
            JubJubScalar::zero(),
            GENERATOR_EXTENDED,
            nonce,
            &[BlsScalar::zero(); PoseidonCipher::capacity()],
            cipher.cipher(),
        );
        verifier.preprocess(&ck)?;

        assert!(verifier.verify(&proof, &vk, &vec![]).is_ok());

        Ok(())
    }
}
