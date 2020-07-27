use dusk_jubjub::AffinePoint;
use dusk_plonk::prelude::BlsScalar;
use hades252::{ScalarStrategy, Strategy, WIDTH};

use std::io;

/// Number of scalars used in a cipher
pub const CIPHER_SIZE: usize = 5;

/// Bytes consumed on serialization of the encrypted data
pub const ENCRYPTED_DATA_SIZE: usize = 32 * CIPHER_SIZE;

/// Maximum number of bits accepted by the encrypt function
pub const MESSAGE_SCALARS: usize = CIPHER_SIZE - 1;

const LENGTH: [u64; 4] = [2u64, 0, 0, 0];
const DOMAIN: [u64; 4] = [0x100000000u64, 0, 0, 0];

/// Encapsulates an encrypted data
///
/// This implementation is optimized for a message containing 2 scalars
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct PoseidonCipher {
    cipher: [BlsScalar; CIPHER_SIZE],
}

impl PoseidonCipher {
    /// Encrypt a pair m0 and m1 provided a secret pair and a nonce
    ///
    /// The message size will be truncated to [`MESSAGE_SCALARS`] bits
    pub fn encrypt(
        message: &[BlsScalar],
        secret: &AffinePoint,
        nonce: &BlsScalar,
    ) -> Self {
        let zero = BlsScalar::zero();
        let mut strategy = ScalarStrategy::new();
        let mut rng = rand::thread_rng();

        let mut state = PoseidonCipher::initial_state(
            secret.get_x(),
            secret.get_y(),
            *nonce,
        );
        let mut cipher = [zero; CIPHER_SIZE];

        strategy.perm(&mut state);

        (0..MESSAGE_SCALARS).for_each(|i| {
            state[i + 1] += if i < message.len() {
                message[i]
            } else {
                BlsScalar::random(&mut rng)
            };

            cipher[i] = state[i + 1];
        });

        strategy.perm(&mut state);
        cipher[MESSAGE_SCALARS] = state[1];

        Self { cipher }
    }

    /// Decrypt a previously encrypted message, provided the shared secret and nonce
    /// used for encryption. If the decryption is not successful, `None` is returned
    pub fn decrypt(
        &self,
        secret: &AffinePoint,
        nonce: &BlsScalar,
    ) -> Option<[BlsScalar; MESSAGE_SCALARS]> {
        let zero = BlsScalar::zero();
        let mut strategy = ScalarStrategy::new();

        let mut state = PoseidonCipher::initial_state(
            secret.get_x(),
            secret.get_y(),
            *nonce,
        );
        let mut message = [zero; MESSAGE_SCALARS];

        strategy.perm(&mut state);

        (0..4).for_each(|i| {
            message[i] = self.cipher[i] - state[i + 1];
            state[i + 1] = self.cipher[i];
        });

        strategy.perm(&mut state);

        if self.cipher[4] == state[1] {
            Some(message)
        } else {
            None
        }
    }

    fn initial_state(
        ks0: BlsScalar,
        ks1: BlsScalar,
        nonce: BlsScalar,
    ) -> [BlsScalar; WIDTH] {
        [
            BlsScalar::from_raw(DOMAIN),
            BlsScalar::from_raw(LENGTH),
            ks0,
            ks1,
            nonce,
        ]
    }
}

impl io::Write for PoseidonCipher {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if buf.len() < CIPHER_SIZE * 32 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let mut bytes = [0u8; 32];
        self.cipher.iter_mut().try_fold(0usize, |mut n, x| {
            n += bytes.as_mut().write(&buf[n..n + 32])?;

            // Constant time option is REALLY inflexible, so this is required
            let scalar = BlsScalar::from_bytes(&bytes);

            if scalar.is_none().into() {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }

            *x = scalar.unwrap();

            Ok(n)
        })
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl io::Read for PoseidonCipher {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if buf.len() < CIPHER_SIZE * 32 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        self.cipher.iter_mut().try_fold(0usize, |mut n, x| {
            n += (&mut x.to_bytes().as_ref()).read(&mut buf[n..n + 32])?;

            Ok(n)
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::{PoseidonCipher, ENCRYPTED_DATA_SIZE, MESSAGE_SCALARS};
    use dusk_jubjub::{AffinePoint, Fr, GENERATOR};
    use dusk_plonk::prelude::BlsScalar;
    use rand::RngCore;
    use std::io::{Read, Write};
    use std::ops::Mul;

    fn gen() -> ([BlsScalar; MESSAGE_SCALARS], AffinePoint, BlsScalar) {
        let mut rng = rand::thread_rng();

        let message = [
            BlsScalar::random(&mut rng),
            BlsScalar::random(&mut rng),
            BlsScalar::random(&mut rng),
            BlsScalar::random(&mut rng),
        ];

        let mut secret = [0u8; 64];
        rng.fill_bytes(&mut secret);
        let secret = Fr::from_bytes_wide(&secret);
        let secret = GENERATOR.to_niels().mul(&secret).into();

        let nonce = BlsScalar::random(&mut rng);

        (message, secret, nonce)
    }

    #[test]
    fn poseidon_encrypt() {
        let (message, secret, nonce) = gen();

        let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt);
    }

    #[test]
    fn poseidon_encrypt_single_bit() {
        let (_, secret, nonce) = gen();
        let message = BlsScalar::random(&mut rand::thread_rng());

        let cipher = PoseidonCipher::encrypt(&[message], &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt[0]);
    }

    #[test]
    fn poseidon_encrypt_overflow() {
        let (_, secret, nonce) = gen();
        let message =
            [BlsScalar::random(&mut rand::thread_rng()); MESSAGE_SCALARS + 1];

        let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message[0..MESSAGE_SCALARS], decrypt);
    }

    #[test]
    fn poseidon_encrypt_fail() {
        let (message, secret, nonce) = gen();
        let (_, wrong_secret, _) = gen();

        let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
        assert!(cipher.decrypt(&wrong_secret, &nonce).is_none());
    }

    #[test]
    fn poseidon_serialize_encrypt() {
        let (message, secret, nonce) = gen();

        let mut cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);

        let mut bytes = vec![0u8; ENCRYPTED_DATA_SIZE];
        cipher.read(bytes.as_mut_slice()).unwrap();

        let mut deser_cipher = PoseidonCipher::default();
        deser_cipher.write(bytes.as_slice()).unwrap();

        assert_eq!(cipher, deser_cipher);

        let decrypt = deser_cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt);
    }
}
