use dusk_bls12_381::Scalar;
use hades252::{ScalarStrategy, Strategy, WIDTH};

use std::io;

/// Number of scalars used in a cipher
pub const CIPHER_SIZE: usize = 5;

/// Bytes consumed on serialization of the encrypted data
pub const ENCRYPTED_DATA_SIZE: usize = 32 * CIPHER_SIZE;

/// Maximum number of bits accepted by the encrypt function
pub const MESSAGE_BITS: usize = CIPHER_SIZE - 1;

/// Perform the key expansion
///
/// `x \in F_p, (a, b) \in F^2_p, key_expand(x) = (a, b)`
pub fn key_expand(secret: &Scalar) -> (Scalar, Scalar) {
    let mut p = [Scalar::zero(); WIDTH];
    p[1] = *secret;

    let mut strategy = ScalarStrategy::new();
    strategy.perm(&mut p);

    (p[1], p[2])
}

/// Encapsulates an encrypted data
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct EncryptedData {
    cipher: [Scalar; CIPHER_SIZE],
}

impl EncryptedData {
    /// Encrypt a pair m0 and m1 provided a secret pair and a nonce
    ///
    /// The message size will be truncated to [`MESSAGE_BITS`] bits
    pub fn encrypt(
        message: &[Scalar],
        secret: &Scalar,
        nonce: &Scalar,
    ) -> Self {
        let zero = Scalar::zero();
        let mut strategy = ScalarStrategy::new();
        let mut rng = rand::thread_rng();

        let (ks0, ks1) = key_expand(secret);

        let mut state = [zero; CIPHER_SIZE];
        let mut cipher = [zero; CIPHER_SIZE];

        state[1] = Scalar::from(5u64);
        state[2] = ks0;
        state[3] = ks1;
        state[4] = *nonce;

        strategy.perm(&mut state);

        (0..MESSAGE_BITS).for_each(|i| {
            state[i + 1] += if i < message.len() {
                message[i]
            } else {
                Scalar::random(&mut rng)
            };

            cipher[i] = state[i + 1];
        });

        strategy.perm(&mut state);
        cipher[MESSAGE_BITS] = state[1];

        Self { cipher }
    }

    /// Decrypt a previously encrypted message, provided the shared secret and nonce
    /// used for encryption. If the decryption is not successful, `None` is returned
    pub fn decrypt(
        &self,
        secret: &Scalar,
        nonce: &Scalar,
    ) -> Option<[Scalar; MESSAGE_BITS]> {
        let zero = Scalar::zero();
        let mut strategy = ScalarStrategy::new();

        let (ks0, ks1) = key_expand(secret);

        let mut state = [zero; CIPHER_SIZE];
        let mut message = [zero; MESSAGE_BITS];

        state[1] = Scalar::from(5u64);
        state[2] = ks0;
        state[3] = ks1;
        state[4] = *nonce;

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
}

impl io::Write for EncryptedData {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if buf.len() < CIPHER_SIZE * 32 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let mut bytes = [0u8; 32];
        self.cipher.iter_mut().try_fold(0usize, |mut n, x| {
            n += bytes.as_mut().write(&buf[n..n + 32])?;

            // Constant time option is REALLY inflexible, so this is required
            let scalar = Scalar::from_bytes(&bytes);

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

impl io::Read for EncryptedData {
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
    use super::{EncryptedData, ENCRYPTED_DATA_SIZE, MESSAGE_BITS};
    use dusk_bls12_381::Scalar;
    use std::io::{Read, Write};

    fn gen() -> ([Scalar; MESSAGE_BITS], Scalar, Scalar) {
        let mut rng = rand::thread_rng();

        let message = [
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
            Scalar::random(&mut rng),
        ];

        let secret = Scalar::random(&mut rng);
        let nonce = Scalar::random(&mut rng);

        (message, secret, nonce)
    }

    #[test]
    fn poseidon_encrypt() {
        let (message, secret, nonce) = gen();

        let cipher = EncryptedData::encrypt(&message, &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt);
    }

    #[test]
    fn poseidon_encrypt_single_bit() {
        let (_, secret, nonce) = gen();
        let message = Scalar::random(&mut rand::thread_rng());

        let cipher = EncryptedData::encrypt(&[message], &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt[0]);
    }

    #[test]
    fn poseidon_encrypt_overflow() {
        let (_, secret, nonce) = gen();
        let message =
            [Scalar::random(&mut rand::thread_rng()); MESSAGE_BITS + 1];

        let cipher = EncryptedData::encrypt(&message, &secret, &nonce);
        let decrypt = cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message[0..MESSAGE_BITS], decrypt);
    }

    #[test]
    fn poseidon_encrypt_fail() {
        let (message, secret, nonce) = gen();

        let cipher = EncryptedData::encrypt(&message, &secret, &nonce);
        assert!(cipher.decrypt(&(secret + Scalar::one()), &nonce).is_none());
    }

    #[test]
    fn poseidon_serialize_encrypt() {
        let (message, secret, nonce) = gen();

        let mut cipher = EncryptedData::encrypt(&message, &secret, &nonce);

        let mut bytes = vec![0u8; ENCRYPTED_DATA_SIZE];
        cipher.read(bytes.as_mut_slice()).unwrap();

        let mut deser_cipher = EncryptedData::default();
        deser_cipher.write(bytes.as_slice()).unwrap();

        assert_eq!(cipher, deser_cipher);

        let decrypt = deser_cipher.decrypt(&secret, &nonce).unwrap();

        assert_eq!(message, decrypt);
    }
}
