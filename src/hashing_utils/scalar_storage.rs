// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! This module defines a Wrap-up over the dusk-bls12_381 to define it's kelvin
//! storage traits

use dusk_plonk::bls12_381::Scalar as BlsScalar;
use kelvin::{ByteHash, Content, Sink, Source};
use std::borrow::Borrow;
use std::io;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// This struct is a Wrapper type over the bls12-381 `Scalar` which has implemented
/// inside the logic to allows `Kelvin` Merkle Trees understand how to store `Scalar`s
/// inside of their leaves.
///
/// This Struct is the one that we will use inside of our SmartContract storage logic to
/// encode/compress all of our Data Structures data into a single `Scalar`.
pub struct StorageScalar(pub BlsScalar);

impl Default for StorageScalar {
    fn default() -> Self {
        StorageScalar(BlsScalar::default())
    }
}

impl Borrow<BlsScalar> for StorageScalar {
    fn borrow(&self) -> &BlsScalar {
        &self.0
    }
}

impl From<&StorageScalar> for StorageScalar {
    fn from(s: &StorageScalar) -> Self {
        s.clone()
    }
}

impl From<u64> for StorageScalar {
    fn from(val: u64) -> StorageScalar {
        StorageScalar(BlsScalar::from(val))
    }
}

// This is implemented since `PoseidonAnnotation` wraps up over `StorageScalar`.
// Therefore, in rust to get the interal `Scalar` from the annotation you'll
// need to call `annotation.0.0` and this is not valid.
// This trait impl solves the problem.
impl Into<BlsScalar> for StorageScalar {
    fn into(self) -> BlsScalar {
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
        source.read_exact(&mut bytes)?;
        let might_be_scalar = BlsScalar::from_bytes(&bytes);
        if might_be_scalar.is_none().unwrap_u8() == 1u8 {
            return Err(std::io::ErrorKind::InvalidData.into());
        };
        // Now it's safe to unwrap.
        return Ok(StorageScalar(might_be_scalar.unwrap()));
    }
}
