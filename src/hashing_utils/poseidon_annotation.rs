// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Helpers for kelvin hashing & storing trait implementations
use super::scalar_storage::StorageScalar;
use crate::merkle_lvl_hash::hash;
use crate::ARITY;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use kelvin::{annotation, annotations::Cardinality, Combine, ErasedAnnotation};
use std::borrow::Borrow;

#[macro_export]
/// Extends `StorageScalar` for a provided type
///
/// Will create a new implementation of the poseidon storage scalar
///
/// The target type must implement `fn hash(&self) -> $scalar`
/// `PoseidonScalar` must implement `From<$scalar>`
///
/// Required libs:
/// * `kelvin`
macro_rules! extend_storage_scalar {
    ($id:ident, $scalar:ty, $type:ty) => {
        #[derive(
            Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Canon,
        )]
        pub struct $id(poseidon252::StorageScalar);

        impl $id {
            pub fn s(&self) -> &$scalar {
                &(&self.0).0
            }

            pub fn s_mut(&mut self) -> &mut $scalar {
                &mut (&mut self.0).0
            }
        }

        impl<'a> From<&'a $type> for $id {
            fn from(bid: &'a $type) -> $id {
                bid.hash().into()
            }
        }

        impl From<&poseidon252::StorageScalar> for $id {
            fn from(s: &poseidon252::StorageScalar) -> Self {
                $id(*s)
            }
        }

        impl From<poseidon252::StorageScalar> for $id {
            fn from(s: poseidon252::StorageScalar) -> Self {
                $id(s)
            }
        }

        impl<'a> From<&'a $type> for poseidon252::StorageScalar {
            fn from(t: &'a $type) -> Self {
                t.hash().into()
            }
        }

        impl From<&$scalar> for $id {
            fn from(s: &$scalar) -> Self {
                $id::from(poseidon252::StorageScalar(*s))
            }
        }

        impl From<$scalar> for $id {
            fn from(s: $scalar) -> Self {
                $id::from(poseidon252::StorageScalar(s))
            }
        }

        impl Into<$scalar> for &$id {
            fn into(self) -> $scalar {
                use std::borrow::Borrow;

                *self.borrow()
            }
        }

        impl Into<$scalar> for $id {
            fn into(self) -> $scalar {
                use std::borrow::Borrow;

                *self.borrow()
            }
        }

        impl std::borrow::Borrow<$scalar> for $id {
            fn borrow(&self) -> &$scalar {
                self.0.borrow()
            }
        }

        impl std::borrow::Borrow<poseidon252::StorageScalar> for $id {
            fn borrow(&self) -> &poseidon252::StorageScalar {
                &self.0
            }
        }

        impl<A> kelvin::Combine<A> for $id {
            fn combine<E>(elements: &[E]) -> Option<Self>
            where
                A: std::borrow::Borrow<Self> + Clone,
                E: kelvin::ErasedAnnotation<A>,
            {
                let mut leaves: [Option<$scalar>; poseidon252::ARITY] =
                    [None; poseidon252::ARITY];

                elements.iter().zip(leaves.iter_mut()).for_each(
                    |(element, leave)| {
                        match element.annotation() {
                            Some(annotation) => {
                                let s: &$id = (*annotation).borrow();
                                *leave = Some(s.into());
                            }
                            None => *leave = None,
                        };
                    },
                );

                let res = poseidon252::merkle_lvl_hash::hash::merkle_level_hash(
                    &leaves,
                );
                Some(res.into())
            }
        }
    };
}

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
