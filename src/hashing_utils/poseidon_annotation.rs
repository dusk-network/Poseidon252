// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! Helpers for kelvin hashing & storing trait implementations
use super::scalar_storage::StorageScalar;
use crate::merkle_lvl_hash::hash;
use crate::ARITY;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use kelvin::{annotation, annotations::Cardinality, Combine, ErasedAnnotation};
use std::borrow::Borrow;
use std::io;

annotation! {
    /// The annotation for the Notes tree is a storagescalar
    /// and a cardinality
    pub struct PoseidonAnnotation {
        scalar: StorageScalar,
        count: Cardinality<u64>,
    }
}

impl<A> Combine<A> for StorageScalar {
    /// This implements the logic that Kelvin needs in order to know how to
    /// hash an entire merkle tree level.
    ///
    /// It includes the generation of the bitflags logic inside of it.
    fn combine<E>(elements: &[E]) -> Option<Self>
    where
        A: Borrow<Self> + Clone,
        E: ErasedAnnotation<A>,
    {
        let mut leaves: [Option<BlsScalar>; ARITY] = [None; ARITY];
        elements
            .iter()
            .zip(leaves.iter_mut())
            .for_each(|(element, leave)| {
                match element.annotation() {
                    Some(annotation) => {
                        let s: &StorageScalar = (*annotation).borrow();
                        *leave = Some(s.0);
                    }
                    None => *leave = None,
                };
            });
        let res = hash::merkle_level_hash(&leaves);
        Some(StorageScalar(res))
    }
}
