//! This module defines a Wrap-up over the dusk-bls12_381 to define it's kelvin
//! storage traits

use dusk_bls12_381::Scalar;
use kelvin::{ByteHash, Content, Sink, Source};
use std::borrow::Borrow;
use std::io;
use std::io::Read;

#[derive(Debug, Clone)]
/// This struct is a Wrapper type over the bls12-381 `Scalar` which has implemented
/// inside the logic to allows `Kelvin` Merkle Trees understand how to store `Scalar`s
/// inside of them leaves.
///
/// This Struct is the one that we will use inside of our SmartContract storage logic to
/// encode/compress all of our Data Structures data into a single `Scalar`.
pub struct StorageScalar(pub Scalar);

impl Default for StorageScalar {
    fn default() -> Self {
        StorageScalar(Scalar::default())
    }
}

impl Borrow<Scalar> for StorageScalar {
    fn borrow(&self) -> &Scalar {
        &self.0
    }
}

// This is implemented since `PoseidonAnnotation` wraps up over `StorageScalar`.
// Therefore, in rust to get the interal `Scalar` from the annotation you'll
// need to call `annotation.0.0` and this is not valid.
// This trait impl solves the problem.
impl Into<Scalar> for StorageScalar {
    fn into(self) -> Scalar {
        self.0
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
        // The solution with iterators is a way more messy.
        // See: https://doc.rust-lang.org/stable/rust-by-example/error/iter_result.html
        for (src, dest) in source.bytes().zip(bytes.iter_mut()) {
            *dest = src?
        }
        Ok(StorageScalar(Scalar::from_bytes(&bytes).unwrap()))
    }
}
