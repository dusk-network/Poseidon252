use dusk_plonk::jubjub::AffinePoint;
use dusk_plonk::prelude::BlsScalar;
use hades252::{ScalarStrategy, Strategy, WIDTH};

use std::io;

/// Maximum number of scalars allowed per message
pub const MESSAGE_CAPACITY: usize = 2;

/// Number of scalars used in a cipher
pub const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;

/// Bytes consumed on serialization of the poseidon cipher
pub const ENCRYPTED_DATA_SIZE: usize = CIPHER_SIZE * 32;

/// Encapsulates an encrypted data
///
/// This implementation is optimized for a message containing 2 scalars
///
/// # Examples
/// ```
/// use dusk_plonk::jubjub::{dhke, ExtendedPoint, GENERATOR};
/// use dusk_plonk::prelude::{BlsScalar, JubJubScalar};
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
pub struct PoseidonCipher {
    cipher: [BlsScalar; CIPHER_SIZE],
}

impl PoseidonCipher {
    /// [`PoseidonCipher`] constructor
    pub fn new(cipher: [BlsScalar; CIPHER_SIZE]) -> Self {
        Self { cipher }
    }

    /// Maximum number of scalars allowed per message
    pub fn capacity() -> usize {
        MESSAGE_CAPACITY
    }

    /// Bytes consumed on serialization of the poseidon cipher
    pub fn serialized_size() -> usize {
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
                BlsScalar::random(&mut rand::thread_rng())
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
    ) -> Option<[BlsScalar; MESSAGE_CAPACITY]> {
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

        if self.cipher[MESSAGE_CAPACITY] == state[1] {
            Some(message)
        } else {
            None
        }
    }

    fn initial_state(
        secret: &AffinePoint,
        nonce: BlsScalar,
    ) -> [BlsScalar; WIDTH] {
        [
            // Domain
            BlsScalar::from_raw([0x100000000u64, 0, 0, 0]),
            // Length
            BlsScalar::from_raw([2u64, 0, 0, 0]),
            secret.get_x(),
            secret.get_y(),
            nonce,
        ]
    }
}

impl io::Write for PoseidonCipher {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if buf.len() < ENCRYPTED_DATA_SIZE {
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
        if buf.len() < ENCRYPTED_DATA_SIZE {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        self.cipher.iter_mut().try_fold(0usize, |n, x| {
            let s = (&mut x.to_bytes().as_ref()).read(&mut buf[n..n + 32])?;

            Ok(n + s)
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::{
        PoseidonCipher, CIPHER_SIZE, ENCRYPTED_DATA_SIZE, MESSAGE_CAPACITY,
    };
    use dusk_plonk::jubjub::{AffinePoint, Fr, GENERATOR};
    use dusk_plonk::prelude::BlsScalar;
    use hades252::WIDTH;
    use rand::RngCore;
    use std::io::{Read, Write};
    use std::ops::Mul;

    fn gen() -> ([BlsScalar; MESSAGE_CAPACITY], AffinePoint, BlsScalar) {
        let mut rng = rand::thread_rng();

        let mut message = [BlsScalar::zero(); MESSAGE_CAPACITY];
        message
            .iter_mut()
            .for_each(|m| *m = BlsScalar::random(&mut rng));

        let mut secret = [0u8; 64];
        rng.fill_bytes(&mut secret);
        let secret = Fr::from_bytes_wide(&secret);
        let secret = GENERATOR.to_niels().mul(&secret).into();

        let nonce = BlsScalar::random(&mut rng);

        (message, secret, nonce)
    }

    #[test]
    fn sanity() {
        // The secret is always a pair with nonce, so the message capacity should be at least 2
        assert!(MESSAGE_CAPACITY > 1);

        // The cipher size only makes sense to be `capacity + 1`
        assert_eq!(CIPHER_SIZE, MESSAGE_CAPACITY + 1);

        // The hades permutation cannot be performed if the cipher is bigger than hades width
        assert!(WIDTH >= CIPHER_SIZE);
    }

    #[test]
    fn encrypt() {
        let (message, secret, nonce) = gen();

        let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt);
    }

    #[test]
    fn single_bit() {
        let (_, secret, nonce) = gen();
        let message = BlsScalar::random(&mut rand::thread_rng());

        let cipher = PoseidonCipher::encrypt(&[message], &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt[0]);
    }

    #[test]
    fn overflow() {
        let (_, secret, nonce) = gen();
        let message =
            [BlsScalar::random(&mut rand::thread_rng()); MESSAGE_CAPACITY + 1];

        let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message[0..MESSAGE_CAPACITY], decrypt);
    }

    #[test]
    fn wrong_key_fail() {
        let (message, secret, nonce) = gen();
        let (_, wrong_secret, _) = gen();

        let cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);
        assert!(cipher.decrypt(&wrong_secret, &nonce).is_none());
    }

    #[test]
    fn serialization() {
        let (message, secret, nonce) = gen();

        let mut cipher = PoseidonCipher::encrypt(&message, &secret, &nonce);

        let mut bytes = vec![0u8; ENCRYPTED_DATA_SIZE];

        let n = cipher.read(bytes.as_mut_slice()).unwrap();
        assert_eq!(n, PoseidonCipher::serialized_size());

        let mut deser_cipher = PoseidonCipher::default();
        let n = deser_cipher.write(bytes.as_slice()).unwrap();
        assert_eq!(n, PoseidonCipher::serialized_size());

        assert_eq!(cipher, deser_cipher);

        let decrypt = deser_cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt);
    }
}
