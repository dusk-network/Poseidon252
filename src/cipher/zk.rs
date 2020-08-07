use super::{PoseidonCipher, CIPHER_SIZE, MESSAGE_CAPACITY};
use dusk_plonk::constraint_system::ecc::Point;
use dusk_plonk::prelude::*;
use hades252::{GadgetStrategy, Strategy};

/// Return a cipher provided the PoseidonCipher encryption parameters
pub fn poseidon_cipher_gadget(
    composer: &mut StandardComposer,
    shared_secret: &Point,
    nonce: Variable,
    message: &[Variable],
) -> [Variable; CIPHER_SIZE] {
    let zero = composer.add_constant_witness(BlsScalar::zero());

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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use dusk_plonk::jubjub::{dhke, ExtendedPoint, GENERATOR};

    use std::ops::Mul;

    #[test]
    fn gadget() -> Result<()> {
        let mut rng = rand::thread_rng();

        // Generate a secret and a public key for Bob
        let bob_secret = JubJubScalar::random(&mut rng);
        let bob_public = GENERATOR.to_niels().mul(&bob_secret);

        // Generate a secret and a public key for Alice
        let alice_secret = JubJubScalar::random(&mut rng);
        let alice_public = GENERATOR.to_niels().mul(&alice_secret);

        // Generate a shared secret
        let shared_secret = dhke(&bob_secret, &alice_public);
        assert_eq!(dhke(&alice_secret, &bob_public), shared_secret);

        // Generate a secret message
        let a = BlsScalar::random(&mut rng);
        let b = BlsScalar::random(&mut rng);
        let message = [a, b];

        // Perform the encryption
        let nonce = BlsScalar::random(&mut rng);
        let cipher = PoseidonCipher::encrypt(&message, &shared_secret, &nonce);

        let pp = PublicParameters::setup(1 << 12, &mut rng).unwrap();
        let (ck, vk) = pp.trim(1 << 12).unwrap();

        let label = b"poseidon-cipher";

        let circuit = |composer: &mut StandardComposer,
                       secret: JubJubScalar,
                       public: ExtendedPoint,
                       nonce: BlsScalar,
                       message: &[BlsScalar],
                       cipher: &[BlsScalar]| {
            let zero = composer.add_constant_witness(BlsScalar::zero());
            let nonce = composer.add_input(nonce);

            let secret = composer.add_input((secret).into());
            let shared_secret = dusk_plonk::constraint_system::ecc::scalar_mul(
                composer, secret, public,
            );

            let mut m = [zero; MESSAGE_CAPACITY];
            message.iter().zip(m.iter_mut()).for_each(|(m, v)| {
                *v = composer.add_input(*m);
            });
            let message = m;

            let cipher_gadget = poseidon_cipher_gadget(
                composer,
                shared_secret.point(),
                nonce,
                &message,
            );

            cipher.iter().zip(cipher_gadget.iter()).for_each(|(c, g)| {
                let x = composer.add_input(*c);
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
        prover.preprocess(&ck).unwrap();
        let proof = prover.prove(&ck).unwrap();

        let mut verifier = Verifier::new(label);

        // TODO - https://github.com/dusk-network/plonk/issues/276
        // After this issue is fixed, should receive bob_public
        circuit(
            verifier.mut_cs(),
            JubJubScalar::zero(),
            alice_public,
            nonce,
            &[BlsScalar::zero(); MESSAGE_CAPACITY],
            cipher.cipher(),
        );
        verifier.preprocess(&ck).unwrap();

        assert!(verifier
            .verify(&proof, &vk, &vec![BlsScalar::zero()])
            .is_ok());

        Ok(())
    }
}
