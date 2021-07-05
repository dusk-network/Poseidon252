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

mod cipher;

#[cfg(test)]
mod tests;

mod zk;
pub use cipher::PoseidonCipher;
pub use zk::{decrypt, encrypt};
