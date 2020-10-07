// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The Merkle Level Hashing is a technique that Poseidon is optimized-by-design
//! to perform.
//!
//! This technique allows us to perform hashes of an entire Merkle Tree using
//! `Hades252` as backend.
//! The technique requires the computation of a `bitflags` element which is always
//! positioned as the first item of the level when we hash it, and it basically generated
//! in respect of the presence or absence of a leaf in the tree level.
//! This allows to prevent hashing collitions.
//!
//! At the moment, this library is designed and optimized to work only with trees of `ARITY`
//! up to 4. **That means that trees with a bigger ARITY SHOULD NEVER be used with this lib.**
//!
//! The module contains the implementation of 4 variants of the same algorithm to support the
//! majority of the configurations that the user may need:
//! - Scalar backend for hashing Merkle Tree levels outside of ZK-Circuits whith two variants:
//! One of them computes the bitflags item while the other assumes that it has already been
//! computed and placed in the first Level position.
//!
//! - `dusk_plonk::Variable` backend for hashing Merkle Tree levels inside of ZK-Circuits,
//!  specifically, PLONK circuits. This implementation comes also whith two variants;
//! One of them computes the bitflags item while the other assumes that it has already been
//! computed and placed in the first Level position.
use crate::merkle_proof::poseidon_branch::PoseidonLevel;
use crate::ARITY;
use dusk_plonk::prelude::*;
use hades252::strategies::*;
use hades252::WIDTH;

/// The `poseidon_hash` function takes a Merkle Tree Level with up to `ARITY`
/// leaves and applies the poseidon hash, using the `hades252::ScalarStragegy` and
/// computing the corresponding bitflags.
pub fn merkle_level_hash(leaves: &[Option<BlsScalar>]) -> BlsScalar {
    let mut h = ScalarStrategy::new();

    let mut perm = [BlsScalar::zero(); WIDTH];
    let mut bit = 1 << WIDTH - 1;
    let mut flag = 0;

    leaves
        .iter()
        .zip(perm.iter_mut().skip(1))
        .for_each(|(l, p)| {
            bit >>= 1;

            if let Some(l) = l {
                flag |= bit;
                *p = *l;
            }
        });

    perm[0] = BlsScalar::from(flag);
    h.perm(&mut perm);

    perm[1]
}

/// The `poseidon_hash` function takes a `PoseidonLevel` which has already computed
/// the bitflags and hashes it returning the resulting `Scalar`.
pub(crate) fn merkle_level_hash_without_bitflags(
    poseidon_level: &PoseidonLevel,
) -> BlsScalar {
    let mut strategy = ScalarStrategy::new();
    let mut res = poseidon_level.leaves.clone();
    strategy.perm(&mut res);
    res[1]
}

/// The `poseidon_hash` function takes a Merkle Tree level with up to `ARITY`
/// leaves and applies the poseidon hash, using the `hades252::GadgetStragegy` and
/// computing the corresponding bitflags.
#[allow(dead_code)]
pub fn merkle_level_hash_gadget(
    composer: &mut StandardComposer,
    leaves: &[Option<Variable>],
) -> Variable {
    let mut accum = 0u64;
    // Define and constraint zero as a fixed-value witness.
    let zero = composer.add_input(BlsScalar::zero());
    composer.constrain_to_constant(zero, BlsScalar::zero(), BlsScalar::zero());
    let mut res = [zero; WIDTH];
    leaves
        .iter()
        .zip(res.iter_mut().skip(1))
        .enumerate()
        .for_each(|(idx, (l, r))| match l {
            Some(var) => {
                *r = *var;
                accum += 1u64 << ((ARITY - 1) - idx);
            }
            None => *r = zero,
        });
    // Set bitflags as first element.
    res[0] = composer.add_input(BlsScalar::from(accum));
    let mut strategy = GadgetStrategy::new(composer);
    strategy.perm(&mut res);
    res[1]
}

/// The `poseidon_hash` function takes a Merkle Tree level which has
/// already computed the bitflags term and applies the poseidon hash,
/// using the `hades252::GadgetStragegy` returning the resulting `Variable`.
pub(crate) fn merkle_level_hash_gadget_without_bitflags(
    composer: &mut StandardComposer,
    leaves: &mut [Variable; WIDTH],
) -> Variable {
    let mut strategy = GadgetStrategy::new(composer);
    strategy.perm(leaves);
    leaves[1]
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use anyhow::Result;

    fn gen_random_merkle_level() -> ([Option<BlsScalar>; ARITY], BlsScalar) {
        let mut input = [Some(BlsScalar::zero()); ARITY];
        input.iter_mut().for_each(|s| {
            *s = Some(BlsScalar::random(&mut rand::thread_rng()))
        });
        // Set to None a leave
        input[2] = None;
        // Compute the level hash
        let output = merkle_level_hash(&input);
        (input, output)
    }

    #[test]
    fn test_merkle_level_bitflags() {
        // Get the inputs and the merkle level hash output
        let (leaves, expected_hash) = gen_random_merkle_level();

        // According to the gen_random_merkle_level, our level will have
        // the following: [Some(leaf), Some(leaf), None, Some(leaf)]
        //
        // This means having a bitflags = 1101 = BlsScalar::from(13u64).
        // So we will compute the hash without the bitflags requirement
        // already providing it. And it should match the expected one.
        let level = PoseidonLevel {
            leaves: [
                // Set the bitflags we already expect
                BlsScalar::from(13u64),
                // Set the rest of the values as the leaf or zero
                leaves[0].unwrap_or(BlsScalar::zero()),
                leaves[1].unwrap_or(BlsScalar::zero()),
                leaves[2].unwrap_or(BlsScalar::zero()),
                leaves[3].unwrap_or(BlsScalar::zero()),
            ],
            // We don't care about this in this specific functionallity test.
            offset: 0usize,
        };
        let obtained_hash = merkle_level_hash_without_bitflags(&level);

        assert_eq!(obtained_hash, expected_hash);
    }

    #[test]
    fn test_merkle_level_gadget_bitflags() -> Result<()> {
        // Gen Public Params and Keys.
        let pub_params =
            PublicParameters::setup(1 << 12, &mut rand::thread_rng())?;
        let (ck, vk) = pub_params.trim(1 << 11)?;

        // Generate input merkle level
        let (level_sacalars, expected_hash) = gen_random_merkle_level();

        let composer_fill = |composer: &mut StandardComposer| {
            // Get the leafs as Variable and add the bitflags that
            // According to the gen_random_merkle_level, our level will have
            // the following: [Some(leaf), Some(leaf), None, Some(leaf)]
            //
            // This means having a bitflags = 1101 = Variable(Scalar::from(13u64)).
            // So we will compute the hash without the bitflags requirement
            // already providing it. And it should match the expected one.
            let mut leaves = [
                // Set the bitflags we already expect
                composer.add_input(BlsScalar::from(13u64)),
                // Set the rest of the values as the leaf or zero
                composer
                    .add_input(level_sacalars[0].unwrap_or(BlsScalar::zero())),
                composer
                    .add_input(level_sacalars[1].unwrap_or(BlsScalar::zero())),
                composer
                    .add_input(level_sacalars[2].unwrap_or(BlsScalar::zero())),
                composer
                    .add_input(level_sacalars[3].unwrap_or(BlsScalar::zero())),
            ];

            let obtained_hash = merkle_level_hash_gadget_without_bitflags(
                composer,
                &mut leaves,
            );
            let expected_hash = composer.add_input(expected_hash);
            // Check with an assert_equal gate that the hash computed is indeed correct.
            composer.assert_equal(obtained_hash, expected_hash);

            // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
            // to zero polynomials.
            composer.add_dummy_constraints();
        };

        // Proving
        let mut prover = Prover::new(b"merkle_gadget_tester");
        composer_fill(prover.mut_cs());
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verification
        let mut verifier = Verifier::new(b"merkle_gadget_tester");
        composer_fill(verifier.mut_cs());
        verifier.preprocess(&ck)?;

        verifier.verify(&proof, &vk, &vec![BlsScalar::zero()])
    }
}
