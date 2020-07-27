use dusk_bls12_381::Scalar;
use hades252::{ScalarStrategy, Strategy};

use std::io;

/// Number of scalars used in a cipher
pub const CIPHER_SIZE: usize = 5;

/// Encapsulates an encrypted data
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct EncryptedData {
    cipher: [Scalar; CIPHER_SIZE],
}

impl EncryptedData {
    /// Encrypt a pair m0 and m1 provided a secret pair and a nonce
    pub fn encrypt(
        m0: &Scalar,
        m1: &Scalar,
        ks0: &Scalar,
        ks1: &Scalar,
        nonce: &Scalar,
    ) -> Self {
        let zero = Scalar::zero();
        let mut strategy = ScalarStrategy::new();
        let mut rng = rand::thread_rng();

        let mut state = [zero, Scalar::from(5u64), *ks0, *ks1, *nonce];
        let mut cipher = [zero, zero, zero, zero, zero];

        strategy.perm(&mut state);

        state[1] += m0;
        state[2] += m1;
        state[3] += Scalar::random(&mut rng);
        state[4] += Scalar::random(&mut rng);

        (0..4).for_each(|i| cipher[i] = state[i + 1]);

        strategy.perm(&mut state);
        cipher[4] = state[1];

        Self { cipher }
    }

    /// Decrypt a previously encrypted message, provided the shared secret and nonce
    /// used for encryption. If the decryption is not successful, `None` is returned
    pub fn decrypt(
        &self,
        ks0: &Scalar,
        ks1: &Scalar,
        nonce: &Scalar,
    ) -> Option<(Scalar, Scalar)> {
        let zero = Scalar::zero();
        let mut strategy = ScalarStrategy::new();

        let mut state = [zero, Scalar::from(5u64), *ks0, *ks1, *nonce];
        let mut message = [zero, zero, zero, zero, zero];

        strategy.perm(&mut state);

        (0..4).for_each(|i| {
            message[i] = self.cipher[i] - state[i + 1];
            state[i + 1] = self.cipher[i];
        });

        strategy.perm(&mut state);

        if self.cipher[4] == state[1] {
            Some((message[0], message[1]))
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
    use super::{EncryptedData, CIPHER_SIZE};
    use dusk_bls12_381::Scalar;
    use std::io::{Read, Write};

    #[test]
    fn poseidon_encrypt() {
        let mut rng = rand::thread_rng();

        let m0 = Scalar::random(&mut rng);
        let m1 = Scalar::random(&mut rng);
        let ks0 = Scalar::random(&mut rng);
        let ks1 = Scalar::random(&mut rng);
        let nonce = Scalar::random(&mut rng);

        let cipher = EncryptedData::encrypt(&m0, &m1, &ks0, &ks1, &nonce);
        let (d0, d1) = cipher.decrypt(&ks0, &ks1, &nonce).unwrap();

        assert_eq!(m0, d0);
        assert_eq!(m1, d1);
    }

    #[test]
    fn poseidon_encrypt_fail() {
        let mut rng = rand::thread_rng();

        let m0 = Scalar::random(&mut rng);
        let m1 = Scalar::random(&mut rng);
        let ks0 = Scalar::random(&mut rng);
        let ks1 = Scalar::random(&mut rng);
        let nonce = Scalar::random(&mut rng);

        let cipher = EncryptedData::encrypt(&m0, &m1, &ks0, &ks1, &nonce);
        assert!(cipher
            .decrypt(&ks0, &(ks1 + Scalar::one()), &nonce)
            .is_none());
    }

    #[test]
    fn poseidon_serialize_encrypt() {
        let mut rng = rand::thread_rng();

        let m0 = Scalar::random(&mut rng);
        let m1 = Scalar::random(&mut rng);
        let ks0 = Scalar::random(&mut rng);
        let ks1 = Scalar::random(&mut rng);
        let nonce = Scalar::random(&mut rng);

        let mut cipher = EncryptedData::encrypt(&m0, &m1, &ks0, &ks1, &nonce);

        let mut bytes = vec![0u8; CIPHER_SIZE * 32];
        cipher.read(bytes.as_mut_slice()).unwrap();

        let mut deser_cipher = EncryptedData::default();
        deser_cipher.write(bytes.as_slice()).unwrap();

        assert_eq!(cipher, deser_cipher);

        let (d0, d1) = deser_cipher.decrypt(&ks0, &ks1, &nonce).unwrap();

        assert_eq!(m0, d0);
        assert_eq!(m1, d1);
    }
}
