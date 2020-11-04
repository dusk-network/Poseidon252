// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;
use dusk_plonk::jubjub::AffinePoint;
use dusk_plonk::prelude::*;
use hades252::{ScalarStrategy, Strategy, WIDTH};

use super::{
    CIPHER_BYTES_SIZE, CIPHER_SIZE, ENCRYPTED_DATA_SIZE, MESSAGE_CAPACITY,
};

pub use super::CipherError;

/// ```ignore
/// Encapsulates an encrypted data
///
/// This implementation is optimized for a message containing 2 scalars
///
/// # Examples
/// use dusk_plonk::jubjub::{dhke, ExtendedPoint, GENERATOR};
/// use dusk_plonk::prelude::*;
/// use poseidon252::cipher::{PoseidonCipher, MESSAGE_CAPACITY};
///
/// use std::ops::Mul;
///
/// fn main() {
///     let mut rng = rand::thread_rng();
///
///     // Generate a secret and a public key for Bob
///     let bob_secret = JubJubScalar::random(&mut rng);
///     let bob_public = GENERATOR.to_niels().mul(&bob_secret);
///
///     // Generate a secret and a public key for Alice
///     let alice_secret = JubJubScalar::random(&mut rng);
///     let alice_public = GENERATOR.to_niels().mul(&alice_secret);
///
///     // Generate a secret message
///     let a = BlsScalar::random(&mut rng);
///     let b = BlsScalar::random(&mut rng);
///     let message = [a, b];
///
///     // Bob's view (sender)
///     // The cipher and nonce are safe to be broadcasted publicly
///     let (cipher, nonce) = sender(&bob_secret, &alice_public, &message);
///
///     // Alice's view (receiver)
///     let decrypted_message =
///         receiver(&alice_secret, &bob_public, &cipher, &nonce);
///
///     // Successful communication
///     assert_eq!(decrypted_message, message);
/// }
///
/// fn sender(
///     sender_secret: &JubJubScalar,
///     receiver_public: &ExtendedPoint,
///     message: &[BlsScalar],
/// ) -> (PoseidonCipher, BlsScalar) {
///     // Use the Diffie-Hellman protocol to generate a shared secret
///     let shared_secret = dhke(sender_secret, receiver_public);
///
///     // Generate a random nonce that will be public
///     let nonce = BlsScalar::random(&mut rand::thread_rng());
///
///     // Encrypt the message
///     let cipher = PoseidonCipher::encrypt(&message, &shared_secret, &nonce);
///
///     (cipher, nonce)
/// }
///
/// fn receiver(
///     receiver_secret: &JubJubScalar,
///     sender_public: &ExtendedPoint,
///     cipher: &PoseidonCipher,
///     nonce: &BlsScalar,
/// ) -> [BlsScalar; MESSAGE_CAPACITY] {
///     // Use the Diffie-Hellman protocol to generate a shared secret
///     let shared_secret = dhke(receiver_secret, sender_public);
///
///     // Decrypt the message
///     cipher
///         .decrypt(&shared_secret, &nonce)
///         .expect("Failed to decrypt!")
/// }
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Default)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct PoseidonCipher {
    cipher: [BlsScalar; CIPHER_SIZE],
}

impl PoseidonCipher {
    /// [`PoseidonCipher`] constructor
    pub fn new(cipher: [BlsScalar; CIPHER_SIZE]) -> Self {
        Self { cipher }
    }

    /// Convert the instance to a bytes representation
    pub fn to_bytes(&self) -> [u8; CIPHER_BYTES_SIZE] {
        let mut bytes = [0u8; CIPHER_BYTES_SIZE];

        self.cipher.iter().enumerate().for_each(|(i, c)| {
            let n = i * 32;
            bytes[n..n + 32].copy_from_slice(&c.to_bytes());
        });

        bytes
    }

    /// Create an instance from a previous `PoseidonCipher::to_bytes` function
    pub fn from_bytes(bytes: &[u8; CIPHER_BYTES_SIZE]) -> Option<Self> {
        let mut cipher: [Option<BlsScalar>; CIPHER_SIZE] = [None; CIPHER_SIZE];
        let mut b = [0u8; 32];

        cipher.iter_mut().enumerate().for_each(|(i, c)| {
            let n = i * 32;
            b.copy_from_slice(&bytes[n..n + 32]);

            let s = BlsScalar::from_bytes(&b);
            if s.is_some().into() {
                c.replace(s.unwrap());
            }
        });

        let mut scalars = [BlsScalar::zero(); CIPHER_SIZE];
        for (c, s) in cipher.iter().zip(scalars.iter_mut()) {
            match c {
                Some(c) => *s = *c,
                None => return None,
            }
        }

        Some(PoseidonCipher::new(scalars))
    }

    /// Maximum number of scalars allowed per message
    pub fn capacity() -> usize {
        MESSAGE_CAPACITY
    }

    /// Bytes consumed on serialization of the poseidon cipher
    pub const fn serialized_size() -> usize {
        ENCRYPTED_DATA_SIZE
    }

    /// Encrypt a slice of scalars into an internal cipher representation
    ///
    /// The message size will be truncated to [`MESSAGE_CAPACITY`] bits
    pub fn encrypt(
        message: &[BlsScalar],
        secret: &AffinePoint,
        nonce: &BlsScalar,
    ) -> Self {
        let zero = BlsScalar::zero();
        let mut strategy = ScalarStrategy::new();

        let mut cipher = [zero; CIPHER_SIZE];
        let mut state = PoseidonCipher::initial_state(secret, *nonce);

        strategy.perm(&mut state);

        (0..MESSAGE_CAPACITY).for_each(|i| {
            state[i + 1] += if i < message.len() {
                message[i]
            } else {
                BlsScalar::zero()
            };

            cipher[i] = state[i + 1];
        });

        strategy.perm(&mut state);
        cipher[MESSAGE_CAPACITY] = state[1];

        PoseidonCipher::new(cipher)
    }

    /// Perform the decrypt of a previously encrypted message.
    ///
    /// Will return `None` if the decryption fails.
    pub fn decrypt(
        &self,
        secret: &AffinePoint,
        nonce: &BlsScalar,
    ) -> Result<[BlsScalar; MESSAGE_CAPACITY], CipherError> {
        let zero = BlsScalar::zero();
        let mut strategy = ScalarStrategy::new();

        let mut message = [zero; MESSAGE_CAPACITY];
        let mut state = PoseidonCipher::initial_state(secret, *nonce);

        strategy.perm(&mut state);

        (0..MESSAGE_CAPACITY).for_each(|i| {
            message[i] = self.cipher[i] - state[i + 1];
            state[i + 1] = self.cipher[i];
        });

        strategy.perm(&mut state);

        if self.cipher[MESSAGE_CAPACITY] != state[1] {
            return Err(CipherError::FailedDecrypt);
        }

        Ok(message)
    }

    /// Getter for the cipher
    pub fn cipher(&self) -> &[BlsScalar; CIPHER_SIZE] {
        &self.cipher
    }

    /// Returns the initial state of the encryption
    pub fn initial_state(
        secret: &AffinePoint,
        nonce: BlsScalar,
    ) -> [BlsScalar; WIDTH] {
        [
            // Domain - Maximum plaintext length of the elements of Fq, as defined in the paper
            BlsScalar::from_raw([0x100000000u64, 0, 0, 0]),
            // The size of the message is constant because any absent input is replaced by zero
            BlsScalar::from_raw([MESSAGE_CAPACITY as u64, 0, 0, 0]),
            secret.get_x(),
            secret.get_y(),
            nonce,
        ]
    }

    /// Returns the initial state of the encryption within a composer circuit
    pub fn initial_state_circuit(
        composer: &mut StandardComposer,
        ks0: Variable,
        ks1: Variable,
        nonce: Variable,
    ) -> [Variable; WIDTH] {
        let domain = BlsScalar::from_raw([0x100000000u64, 0, 0, 0]);
        let domain = composer.add_witness_to_circuit_description(domain);

        let length = BlsScalar::from_raw([MESSAGE_CAPACITY as u64, 0, 0, 0]);
        let length = composer.add_witness_to_circuit_description(length);

        [domain, length, ks0, ks1, nonce]
    }
}
