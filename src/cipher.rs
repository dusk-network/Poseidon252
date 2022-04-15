// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Dusk-Poseidon Cipher
//!
//! Encryption/decryption implementation with Dusk-Poseidon backend.
//!
//! This implementation is optimized for a message containing 2 scalars.
//!
//! ## Shared secret
//!
//! The shared secret is a point on the JubJub curve on the affine form.
//!
//! This implementation does not cover the shared secret derivation strategy.
//!
//! The suggestion is to use a Diffie-Hellman key exchange, as shown in the example. Check [dusk-jubjub](https://github.com/dusk-network/jubjub) for further reference.
//!
//! ## Example
//!
//! ```rust
//! use core::ops::Mul;
//! use dusk_bls12_381::BlsScalar;
//! use dusk_jubjub::{dhke, JubJubExtended, JubJubScalar, GENERATOR};
//! use dusk_poseidon::cipher::PoseidonCipher;
//! use rand_core::OsRng;
//!
//! fn sender(
//!     sender_secret: &JubJubScalar,
//!     receiver_public: &JubJubExtended,
//!     message: &[BlsScalar],
//! ) -> (PoseidonCipher, BlsScalar) {
//!     // Use the Diffie-Hellman protocol to generate a shared secret
//!     let shared_secret = dhke(sender_secret, receiver_public);
//!
//!     // Generate a random nonce that will be public
//!     let nonce = BlsScalar::random(&mut OsRng);
//!
//!     // Encrypt the message
//!     let cipher = PoseidonCipher::encrypt(&message, &shared_secret, &nonce);
//!
//!     (cipher, nonce)
//! }
//!
//! fn receiver(
//!     receiver_secret: &JubJubScalar,
//!     sender_public: &JubJubExtended,
//!     cipher: &PoseidonCipher,
//!     nonce: &BlsScalar,
//! ) -> [BlsScalar; PoseidonCipher::capacity()] {
//!     // Use the Diffie-Hellman protocol to generate a shared secret
//!     let shared_secret = dhke(receiver_secret, sender_public);
//!
//!     // Decrypt the message
//!     cipher
//!         .decrypt(&shared_secret, &nonce)
//!         .expect("Failed to decrypt!")
//! }
//!
//! let mut rng = OsRng;
//!
//! // Generate a secret and a public key for Bob
//! let bob_secret = JubJubScalar::random(&mut rng);
//! let bob_public = GENERATOR.to_niels().mul(&bob_secret);
//!
//! // Generate a secret and a public key for Alice
//! let alice_secret = JubJubScalar::random(&mut rng);
//! let alice_public = GENERATOR.to_niels().mul(&alice_secret);
//!
//! // Generate a secret message
//! let a = BlsScalar::random(&mut rng);
//! let b = BlsScalar::random(&mut rng);
//! let message = [a, b];
//!
//! // Bob's view (sender)
//! // The cipher and nonce are safe to be broadcasted publicly
//! let (cipher, nonce) = sender(&bob_secret, &alice_public, &message);
//!
//! // Alice's view (receiver)
//! let decrypted_message = receiver(&alice_secret, &bob_public, &cipher, &nonce);
//!
//! // Successful communication
//! assert_eq!(decrypted_message, message);
//! ```

use crate::Error;

#[cfg(feature = "canon")]
use canonical_derive::Canon;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_hades::{ScalarStrategy, Strategy};
use dusk_jubjub::JubJubAffine;

const MESSAGE_CAPACITY: usize = 13;
const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;
const CIPHER_BYTES_SIZE: usize = CIPHER_SIZE * BlsScalar::SIZE;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Default)]
#[cfg_attr(feature = "canon", derive(Canon))]
/// Encapsulates an encrypted data
pub struct PoseidonCipher {
    cipher: [BlsScalar; CIPHER_SIZE],
}

impl Serializable<CIPHER_BYTES_SIZE> for PoseidonCipher {
    type Error = BytesError;
    /// Convert the instance to a bytes representation
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];

        self.cipher.iter().enumerate().for_each(|(i, c)| {
            let n = i * BlsScalar::SIZE;
            bytes[n..n + BlsScalar::SIZE].copy_from_slice(&c.to_bytes());
        });

        bytes
    }

    /// Create an instance from a previous `PoseidonCipher::to_bytes` function
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut cipher: [BlsScalar; CIPHER_SIZE] =
            [BlsScalar::zero(); CIPHER_SIZE];

        for (i, scalar) in cipher.iter_mut().enumerate() {
            let idx = i * BlsScalar::SIZE;
            let len = idx + BlsScalar::SIZE;
            *scalar = BlsScalar::from_slice(&bytes[idx..len])?;
        }

        Ok(Self::new(cipher))
    }
}

impl PoseidonCipher {
    /// [`PoseidonCipher`] constructor
    pub const fn new(cipher: [BlsScalar; CIPHER_SIZE]) -> Self {
        Self { cipher }
    }

    /// Maximum number of scalars allowed per message
    pub const fn capacity() -> usize {
        MESSAGE_CAPACITY
    }

    /// Number of scalars used in a cipher
    pub const fn cipher_size() -> usize {
        CIPHER_SIZE
    }

    /// Number of bytes used by from/to bytes `PoseidonCipher` function
    pub const fn cipher_size_bytes() -> usize {
        CIPHER_BYTES_SIZE
    }

    /// Returns the initial state of the encryption
    pub fn initial_state(
        secret: &JubJubAffine,
        nonce: BlsScalar,
    ) -> [BlsScalar; dusk_hades::WIDTH] {
        [
            // Domain - Maximum plaintext length of the elements of Fq, as
            // defined in the paper
            BlsScalar::from_raw([0x100000000u64, 0, 0, 0]),
            // The size of the message is constant because any absent input is
            // replaced by zero
            BlsScalar::from_raw([MESSAGE_CAPACITY as u64, 0, 0, 0]),
            secret.get_x(),
            secret.get_y(),
            nonce,
        ]
    }

    /// Getter for the cipher
    pub const fn cipher(&self) -> &[BlsScalar; CIPHER_SIZE] {
        &self.cipher
    }

    /// Encrypt a slice of scalars into an internal cipher representation
    ///
    /// The message size will be truncated to [`PoseidonCipher::capacity()`]
    /// bits
    pub fn encrypt(
        message: &[BlsScalar],
        secret: &JubJubAffine,
        nonce: &BlsScalar,
    ) -> Self {
        let zero = BlsScalar::zero();
        let mut strategy = ScalarStrategy::new();

        let count= (MESSAGE_CAPACITY + 3) / 4;

        let mut cipher = [zero; CIPHER_SIZE];
        let mut state = PoseidonCipher::initial_state(secret, *nonce);


        (0..count).for_each(|i| {

            strategy.perm(&mut state);

            (0..4).for_each(|j| {
                if 4*i + j < MESSAGE_CAPACITY {
                    state[j + 1] += if 4 * i + j < message.len() {
                        message[4*i + j]
                    } else {
                        BlsScalar::zero()
                    };
                    cipher[4*i + j] = state[j + 1];
                }
            });
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
        secret: &JubJubAffine,
        nonce: &BlsScalar,
    ) -> Result<[BlsScalar; MESSAGE_CAPACITY], Error> {
        let zero = BlsScalar::zero();
        let mut strategy = ScalarStrategy::new();

        let mut message = [zero; MESSAGE_CAPACITY];
        let mut state = PoseidonCipher::initial_state(secret, *nonce);

        let count= (MESSAGE_CAPACITY + 3) / 4;

        (0..count).for_each(|i| {

            strategy.perm(&mut state);

            (0..4).for_each(|j| {
                if 4*i + j < MESSAGE_CAPACITY {
                    message[4*i + j] = self.cipher[4*i + j] - state[j + 1];
                    state[j + 1] = self.cipher[4*i + j];
                }
            });
        });

        strategy.perm(&mut state);

        if self.cipher[MESSAGE_CAPACITY] != state[1] {
            return Err(Error::CipherDecryptionFailed);
        }

        Ok(message)
    }
}

#[cfg(feature = "alloc")]
mod zk;

#[cfg(feature = "alloc")]
pub use zk::{decrypt, encrypt};
