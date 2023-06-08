// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Implement a merkle tree using the poseidon hash function specialized for
//! merkle trees.

use dusk_merkle::Aggregate;
use dusk_plonk::prelude::*;

use crate::merkle::{gadget as merkle_gadget, hash as merkle_hash};

/// An alias for a tree containing `Item<T>`.
pub type Tree<T, const H: usize, const A: usize> =
    dusk_merkle::Tree<Item<T>, H, A>;

/// An alias for an opening of a tree containing `Item<T>`.
pub type Opening<T, const H: usize, const A: usize> =
    dusk_merkle::Opening<Item<T>, H, A>;

/// A type that wraps a piece of data `T` together with a poseidon hash - i.e. a
/// [`BlsScalar`].
///
/// It implements [`Aggregate`] for any `T` that also implements the trait,
/// allowing for the construction of a poseidon tree without the need to define
/// where the aggregation of hashes is predefined.
///
/// # Example
/// ```rust
/// use dusk_bls12_381::BlsScalar;
/// use dusk_poseidon::merkle::tree::{Item, Tree as PoseidonTree};
/// use dusk_poseidon::sponge;
/// use dusk_merkle::Aggregate;
///
/// struct Data(BlsScalar);
///
/// impl From<Data> for Item<Data> {
///     fn from(data: Data) -> Self {
///         Item {
///             hash: sponge::hash(&[data.0]),
///             data,
///         }
///     }
/// }
///
/// impl<const A: usize> Aggregate<A> for Data {
///     const EMPTY_SUBTREE: Data = Data(BlsScalar::zero());
///
///     fn aggregate(items: [&Self; A]) -> Self {
///         Self(items.iter().map(|d| d.0).sum())
///     }
/// }
///
/// const H: usize = 17;
/// const A: usize = 4;
/// type Tree = PoseidonTree<Data, H, A>;
///
/// let mut tree = Tree::new();
/// tree.insert(42, Data(BlsScalar::one()));
/// tree.insert(7, Data(BlsScalar::one()));
/// tree.insert(0xbeef, Data(BlsScalar::one()));
/// ```
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Item<T> {
    /// the hash field of the poseidon item
    pub hash: BlsScalar,
    /// the generic data field of the poseidon item
    pub data: T,
}

impl<T> Item<T> {
    /// Create a new Item for the merkle tree
    pub fn new(hash: BlsScalar, data: T) -> Self {
        Self { hash, data }
    }
}

impl<T, const A: usize> Aggregate<A> for Item<T>
where
    T: Aggregate<A>,
{
    const EMPTY_SUBTREE: Self = Item {
        hash: BlsScalar::zero(),
        data: T::EMPTY_SUBTREE,
    };

    fn aggregate(items: [&Self; A]) -> Self {
        let empty = &T::EMPTY_SUBTREE;

        let mut level_hashes = [BlsScalar::zero(); A];
        let mut level_data = [empty; A];

        // grab hashes and data
        items.into_iter().enumerate().for_each(|(i, item)| {
            level_hashes[i] = item.hash;
            level_data[i] = &item.data;
        });

        // create new aggregated item
        Item {
            hash: merkle_hash(&level_hashes),
            data: T::aggregate(level_data),
        }
    }
}

/// Builds the gadget for the poseidon opening and returns the computed root.
pub fn opening_gadget<C, T, const H: usize, const A: usize>(
    composer: &mut C,
    opening: &Opening<T, H, A>,
    leaf: Witness,
) -> Witness
where
    C: Composer,
    T: Aggregate<A> + Clone,
{
    // append the siblings and position to the circuit
    let mut level_witnesses = [[C::ZERO; A]; H];
    // if i == position: pos_bits[i] = 1 else: pos_bits[i] = 0
    let mut pos_bits = [[C::ZERO; A]; H];
    for h in (0..H).rev() {
        let level = &opening.branch()[h];
        for (i, item) in level.iter().enumerate() {
            if i == opening.positions()[h] {
                pos_bits[h][i] = composer.append_witness(BlsScalar::one());
            } else {
                pos_bits[h][i] = composer.append_witness(BlsScalar::zero());
            }

            level_witnesses[h][i] = composer.append_witness(item.hash);
            // ensure that the entries of pos_bits are either 0 or 1
            composer.component_boolean(pos_bits[h][i]);
        }

        // ensure there is *exactly* one bit turned on in the array, by
        // checking that the sum of all position bits equals 1
        let constraint = Constraint::new()
            .left(1)
            .a(pos_bits[h][0])
            .right(1)
            .b(pos_bits[h][1])
            .fourth(1)
            .d(pos_bits[h][2]);
        let mut sum = composer.gate_add(constraint);
        let constraint =
            Constraint::new().left(1).a(sum).right(1).b(pos_bits[h][3]);
        sum = composer.gate_add(constraint);
        composer.assert_equal_constant(sum, BlsScalar::one(), None);
    }

    // keep track of the computed hash along our path with needle
    let mut needle = leaf;
    for h in (0..H).rev() {
        for i in 0..A {
            // assert that:
            // pos_bits[h][i] * level_hash[i] = pos_bits[h][i] * needle
            let constraint = Constraint::new()
                .mult(1)
                .a(pos_bits[h][i])
                .b(level_witnesses[h][i]);
            let result = composer.gate_mul(constraint);
            let constraint =
                Constraint::new().mult(1).a(pos_bits[h][i]).b(needle);
            let needle_result = composer.gate_mul(constraint);
            // ensure the computed hash matches the stored one
            composer.assert_equal(result, needle_result);
        }

        // hash the current level
        needle = merkle_gadget(composer, &level_witnesses[h]);
    }

    // return the computed root as a witness in the circuit
    needle
}
