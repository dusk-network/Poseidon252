// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module contains an implementation of the `Hades252`
//! strategy algorithm specifically designed to work outside of
//! Rank 1 Constraint Systems (R1CS) or other custom Constraint
//! Systems such as Add/Mul/Custom plonk gate-circuits.
//!
//! The inputs of the permutation function have to be explicitly
//! over the BlsScalar Field of the bls12_381 curve so working over
//! `Fq = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.

use dusk_bls12_381::BlsScalar;

use crate::hades::{PARTIAL_ROUNDS, ROUND_CONSTANTS, TOTAL_FULL_ROUNDS};

/// Strategy for zero-knowledge plonk circuits
#[cfg(feature = "zk")]
mod gadget;

/// Strategy for scalars
mod scalar;

#[cfg(feature = "zk")]
pub use gadget::GadgetStrategy;
pub use scalar::ScalarStrategy;

/// Defines the Hades252 strategy algorithm.
pub trait Strategy<T: Clone + Copy> {
    /// Fetch the next round constant from an iterator
    fn next_c<'b, I>(constants: &mut I) -> BlsScalar
    where
        I: Iterator<Item = &'b BlsScalar>,
    {
        constants
            .next()
            .copied()
            .expect("Hades252 out of ARK constants")
    }

    /// Add round keys to a set of `StrategyInput`.
    ///
    /// This round key addition also known as `ARK` is used to
    /// reach `Confusion and Diffusion` properties for the algorithm.
    ///
    /// Basically it allows to destroy any connection between the
    /// inputs and the outputs of the function.
    fn add_round_key<'b, I>(&mut self, constants: &mut I, words: &mut [T])
    where
        I: Iterator<Item = &'b BlsScalar>;

    /// Computes `input ^ 5 (mod Fp)`
    ///
    /// The modulo depends on the input you use. In our case
    /// the modulo is done in respect of the `bls12_381 scalar field`
    ///  == `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`.
    fn quintic_s_box(&mut self, value: &mut T);

    /// Multiply the values for MDS matrix during the
    /// full rounds application.
    fn mul_matrix<'b, I>(&mut self, constants: &mut I, values: &mut [T])
    where
        I: Iterator<Item = &'b BlsScalar>;

    /// Applies a `Partial Round` also known as a
    /// `Partial S-Box layer` to a set of inputs.
    ///
    /// ### A partial round has 3 steps on every iteration:
    ///
    /// - Add round keys to each word. Also known as `ARK`.
    /// - Apply `quintic S-Box` **just to the last element of
    /// the words generated from the first step.** This is also known
    /// as a `Sub Words` operation.
    /// - Multiplies the output words from the second step by
    /// the `MDS_MATRIX`.
    /// This is known as the `Mix Layer`.
    fn apply_partial_round<'b, I>(&mut self, constants: &mut I, words: &mut [T])
    where
        I: Iterator<Item = &'b BlsScalar>,
    {
        let last = words.len() - 1;

        // Add round keys to each word
        self.add_round_key(constants, words);

        // Then apply quintic s-box
        self.quintic_s_box(&mut words[last]);

        // Multiply this result by the MDS matrix
        self.mul_matrix(constants, words);
    }

    /// Applies a `Full Round` also known as a
    /// `Full S-Box layer` to a set of inputs.
    ///
    /// A full round has 3 steps on every iteration:
    ///
    /// - Add round keys to each word. Also known as `ARK`.
    /// - Apply `quintic S-Box` **to all of the words generated
    /// from the first step.**
    /// This is also known as a `Sub Words` operation.
    /// - Multiplies the output words from the second step by
    /// the `MDS_MATRIX`.
    /// This is known as the `Mix Layer`.
    fn apply_full_round<'a, I>(&mut self, constants: &mut I, words: &mut [T])
    where
        I: Iterator<Item = &'a BlsScalar>,
    {
        // Add round keys to each word
        self.add_round_key(constants, words);

        // Then apply quintic s-box
        words.iter_mut().for_each(|w| self.quintic_s_box(w));

        // Multiply this result by the MDS matrix
        self.mul_matrix(constants, words);
    }

    /// Applies a `permutation-round` of the `Hades252` strategy.
    ///
    /// It returns a vec of `WIDTH` outputs as a result which should be
    /// a randomly permuted version of the input.
    ///
    /// In general, the same round function is iterated enough times
    /// to make sure that any symmetries and structural properties that
    /// might exist in the round function vanish.
    ///
    /// This `permutation` is a 3-step process that:
    ///
    /// - Applies twice the half of the `FULL_ROUNDS`
    /// (which can be understood as linear ops).
    ///
    /// - In the middle step it applies the `PARTIAL_ROUDS`
    /// (which can be understood as non-linear ops).
    ///
    /// This structure allows to minimize the number of non-linear
    /// ops while mantaining the security.
    fn perm(&mut self, data: &mut [T]) {
        let mut constants = ROUND_CONSTANTS.iter();

        // Apply R_f full rounds
        for _ in 0..TOTAL_FULL_ROUNDS / 2 {
            self.apply_full_round(&mut constants, data);
        }

        // Apply R_P partial rounds
        for _ in 0..PARTIAL_ROUNDS {
            self.apply_partial_round(&mut constants, data);
        }

        // Apply R_f full rounds
        for _ in 0..TOTAL_FULL_ROUNDS / 2 {
            self.apply_full_round(&mut constants, data);
        }
    }

    /// Return the total rounds count
    fn rounds() -> usize {
        TOTAL_FULL_ROUNDS + PARTIAL_ROUNDS
    }
}
