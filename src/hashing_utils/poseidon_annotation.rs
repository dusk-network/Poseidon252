//! Helpers for kelvin hashing & storing trait implementations
use super::scalar_storage::StorageScalar;
use crate::merkle_lvl_hash::hash;
use crate::ARITY;
use dusk_bls12_381::Scalar;
use kelvin::{ByteHash, Combine, Content, ErasedAnnotation, Sink, Source, KV};
use std::borrow::Borrow;
use std::io;
use std::io::Read;

#[derive(Clone, Debug)]
/// Wrapping struct that defines used to implement over it
/// the hashing logic that Kelvin needs in order to provide
/// Merkle Paths as `Branch` using Poseidon as the main Hasing
/// algorithm.
pub struct PoseidonAnnotation(pub StorageScalar);

impl Borrow<StorageScalar> for PoseidonAnnotation {
    fn borrow(&self) -> &StorageScalar {
        &self.0
    }
}

impl<A> Combine<A> for PoseidonAnnotation {
    /// This implements the logic that Kelvin needs in order to know how to
    /// hash an entire merkle tree level.
    ///
    /// It includes the generation of the bitflags logic inside of it.
    fn combine<E>(elements: &[E]) -> Option<Self>
    where
        A: Borrow<Self> + Clone,
        E: ErasedAnnotation<A>,
    {
        let mut leaves: [Option<Scalar>; ARITY] = [None; ARITY];
        elements
            .iter()
            .zip(leaves.iter_mut())
            .for_each(|(element, leave)| {
                match element.annotation() {
                    Some(annotation) => {
                        let h: &PoseidonAnnotation = (*annotation).borrow();
                        *leave = Some(h.inner().0);
                    }
                    None => *leave = None,
                };
            });
        let res = hash::merkle_level_hash(&leaves);
        Some(PoseidonAnnotation(StorageScalar(res)))
    }
}

impl<H> Content<H> for PoseidonAnnotation
where
    H: ByteHash,
{
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        self.inner().0.to_bytes().persist(sink)
    }
    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        // The solution with iterators is a way more messy.
        // See: https://doc.rust-lang.org/stable/rust-by-example/error/iter_result.html
        source.read_exact(&mut bytes)?;
        let might_be_scalar = Scalar::from_bytes(&bytes);
        if might_be_scalar.is_none().unwrap_u8() == 1u8 {
            return Err(std::io::ErrorKind::InvalidData.into());
        };
        // Now it's safe to unwrap.
        return Ok(PoseidonAnnotation(StorageScalar(might_be_scalar.unwrap())));
    }
}

impl<T> From<&KV<T, StorageScalar>> for PoseidonAnnotation {
    fn from(kv: &KV<T, StorageScalar>) -> Self {
        PoseidonAnnotation(kv.val.clone())
    }
}

impl From<&Scalar> for PoseidonAnnotation {
    fn from(scalar: &Scalar) -> Self {
        PoseidonAnnotation(StorageScalar(scalar.clone()))
    }
}

impl From<&StorageScalar> for PoseidonAnnotation {
    fn from(stor_scalar: &StorageScalar) -> Self {
        PoseidonAnnotation(stor_scalar.clone())
    }
}

impl PoseidonAnnotation {
    fn inner(&self) -> StorageScalar {
        self.0.clone()
    }
}
