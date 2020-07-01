use dusk_bls12_381::Scalar;

use std::io;

/// Encapsulates an encrypted data
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    a: Scalar,
    b: Scalar,
}

impl EncryptedData {
    /// Perform the encryption of a given message provided a secret and a nonce
    pub fn encrypt(message: &Scalar, secret: &Scalar, nonce: &Scalar) -> Self {
        let a = *message;
        let b = secret + nonce;

        Self { a, b }
    }

    /// Decrypt a previously encrypted message, provided the shared secret and nonce
    /// used for encryption. If the decryption is not successful, `None` is returned
    pub fn decrypt(&self, secret: &Scalar, nonce: &Scalar) -> Option<Scalar> {
        if self.b == secret + nonce {
            Some(self.a)
        } else {
            None
        }
    }
}

impl io::Write for EncryptedData {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if buf.len() < 64 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];

        let mut n = a.as_mut().write(&buf[..32])?;
        n += b.as_mut().write(&buf[32..])?;

        // Constant time option is REALLY inflexible, so this is required
        let a = Scalar::from_bytes(&a);

        if a.is_none().into() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        self.a = a.unwrap();

        let b = Scalar::from_bytes(&b);

        if b.is_none().into() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        self.b = b.unwrap();

        Ok(n)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl io::Read for EncryptedData {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize, io::Error> {
        let a = (&mut self.a.to_bytes().as_ref()).read(&mut buf)?;
        let b = (&mut self.b.to_bytes().as_ref()).read(&mut buf)?;

        Ok(a + b)
    }
}
