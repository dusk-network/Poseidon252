//! This module defines a Wrap-up over the dusk-bls12_381 to define it's kelvin
//! storage traits

use dusk_bls12_381::Scalar;
use kelvin::{ByteHash, Content, Sink, Source};
use std::io;
use std::io::Read;

#[derive(Debug, Clone)]
pub(crate) struct StorageScalar(pub(crate) Scalar);

impl From<Scalar> for StorageScalar {
    fn from(scalar: Scalar) -> StorageScalar {
        StorageScalar(scalar)
    }
}

// Implements logic for storing Scalar inside of kelvin
impl<H> Content<H> for StorageScalar
where
    H: ByteHash,
{
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        self.0.to_bytes().persist(sink)
    }
    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        for (idx, byte) in source.bytes().enumerate() {
            bytes[idx] = byte.unwrap();
        }
        Ok(StorageScalar(Scalar::from_bytes(&bytes).unwrap()))
    }
}
