// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::Error;

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_hades::strategies::{ScalarStrategy, Strategy};
use dusk_jubjub::JubJubAffine;

const MESSAGE_CAPACITY: usize = 2;
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
        secret: &JubJubAffine,
        nonce: &BlsScalar,
    ) -> Result<[BlsScalar; MESSAGE_CAPACITY], Error<()>> {
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
            return Err(Error::CipherDecryptionFailed);
        }

        Ok(message)
    }
}
