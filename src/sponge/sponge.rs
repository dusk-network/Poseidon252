// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Sponge hash and gadget definition

use dusk_bls12_381::BlsScalar;
use hades252::{ScalarStrategy, Strategy, WIDTH};

#[cfg(feature = "std")]
use dusk_plonk::prelude::*;

#[cfg(feature = "std")]
use hades252::GadgetStrategy;

/// The `hash` function takes an arbitrary number of Scalars and returns the hash, using the
/// `Hades` ScalarStragegy.
///
/// As the paper definition, the capacity `c` is set to [`WIDTH`], and `r` is set to `c - 1`.
///
/// Considering `r` is set to `c - 1`, the first bit will be the capacity and will have no message
/// addition, and the remainder bits of the permutation will have the corresponding element of the
/// chunk added.
///
/// The last permutation will append `1` to the message as a padding separator value. The padding
/// values will be zeroes. To avoid collision, the padding will imply one additional permutation
/// in case `|m|` is a multiple of `r`.
pub fn sponge_hash(messages: &[BlsScalar]) -> BlsScalar {
    let mut h = ScalarStrategy::new();
    let mut state = [BlsScalar::zero(); WIDTH];

    // If exists an `m` such as `m · (WIDTH - 1) == l`, then the last iteration index should be
    // `m - 1`.
    //
    // In other words, if `l` is a multiple of `WIDTH - 1`, then the last iteration of the chunk
    // should have an extra appended padding `1`.
    let l = messages.len();
    let m = l / (WIDTH - 1);
    let n = m * (WIDTH - 1);
    let last_iteration = if l == n {
        m.saturating_sub(1)
    } else {
        l / (WIDTH - 1)
    };

    messages
        .chunks(WIDTH - 1)
        .enumerate()
        .for_each(|(i, chunk)| {
            // Last chunk should have an added `1` followed by zeroes, if there is room for such
            if i == last_iteration && chunk.len() < WIDTH - 1 {
                state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                    *s += c;
                });

                state[chunk.len() + 1] += BlsScalar::one();

                h.perm(&mut state);
            // If its the last iteration and there is no available room to append `1`, then there
            // must be an extra permutation for the padding
            } else if i == last_iteration {
                state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                    *s += c;
                });

                h.perm(&mut state);

                state[1] += BlsScalar::one();

                h.perm(&mut state);
            // If its not the last permutation, add the chunk of the message to the corresponding
            // `r` elements
            } else {
                state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                    *s += c;
                });

                h.perm(&mut state);
            }
        });

    state[1]
}

#[cfg(feature = "std")]
/// Mirror the implementation of [`sponge_hash`] inside of a PLONK circuit.
///
/// The circuit will be defined by the length of `messages`. This means that a pre-computed circuit
/// will not behave generically for different messages sizes.
///
/// The expected usage is the length of the message to be known publically as the circuit
/// definition. Hence, the padding value `1` will be appended as a circuit description.
///
/// The returned value is the hashed witness data computed as a variable.
pub fn sponge_hash_gadget(
    composer: &mut StandardComposer,
    messages: &[Variable],
) -> Variable {
    // Create and constrait one and zero as witnesses.
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());

    let mut state = [zero; WIDTH];

    let l = messages.len();
    let m = l / (WIDTH - 1);
    let n = m * (WIDTH - 1);
    let last_iteration = if l == n { m - 1 } else { l / (WIDTH - 1) };

    messages
        .chunks(WIDTH - 1)
        .enumerate()
        .for_each(|(i, chunk)| {
            if i == last_iteration && chunk.len() < WIDTH - 1 {
                state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                    *s = composer.add(
                        (BlsScalar::one(), *s),
                        (BlsScalar::one(), *c),
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );
                });

                state[chunk.len() + 1] = composer.add(
                    (BlsScalar::one(), state[chunk.len() + 1]),
                    (BlsScalar::zero(), zero),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                );

                GadgetStrategy::new(composer).perm(&mut state);
            } else if i == last_iteration {
                state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                    *s = composer.add(
                        (BlsScalar::one(), *s),
                        (BlsScalar::one(), *c),
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );
                });

                GadgetStrategy::new(composer).perm(&mut state);

                state[1] = composer.add(
                    (BlsScalar::one(), state[1]),
                    (BlsScalar::zero(), zero),
                    BlsScalar::one(),
                    BlsScalar::zero(),
                );

                GadgetStrategy::new(composer).perm(&mut state);
            } else {
                state[1..].iter_mut().zip(chunk.iter()).for_each(|(s, c)| {
                    *s = composer.add(
                        (BlsScalar::one(), *s),
                        (BlsScalar::one(), *c),
                        BlsScalar::zero(),
                        BlsScalar::zero(),
                    );
                });

                GadgetStrategy::new(composer).perm(&mut state);
            }
        });

    state[1]
}

#[cfg(test)]
#[cfg(feature = "std")]
mod tests {
    use anyhow::Result;
    use hades252::WIDTH;

    use super::*;

    const CAPACITY: usize = 1 << 12;

    fn poseidon_sponge_params<const N: usize>() -> ([BlsScalar; N], BlsScalar) {
        let mut input = [BlsScalar::zero(); N];
        input
            .iter_mut()
            .for_each(|s| *s = BlsScalar::random(&mut rand::thread_rng()));
        let output = sponge_hash(&input);
        (input, output)
    }

    // Checks that the result of the hades permutation is the same as the one obtained by
    // the sponge gadget
    fn sponge_gadget_tester<const N: usize>(
        i: &[BlsScalar],
        out: BlsScalar,
        composer: &mut StandardComposer,
    ) {
        let zero = composer.add_input(BlsScalar::zero());
        composer.constrain_to_constant(
            zero,
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        let mut i_var = vec![zero; N];
        i.iter().zip(i_var.iter_mut()).for_each(|(i, v)| {
            *v = composer.add_input(*i);
        });

        let o_var = composer.add_input(out);

        // Apply Poseidon Sponge hash to the inputs
        let computed_o_var = sponge_hash_gadget(composer, &i_var);

        // Check that the Gadget sponge hash result = Scalar sponge hash result
        composer.add_gate(
            o_var,
            computed_o_var,
            zero,
            BlsScalar::one(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
    }

    #[test]
    fn sponge_gadget_width_3() -> Result<()> {
        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(CAPACITY, &mut rand::thread_rng())?;
        let (ck, vk) = public_parameters.trim(CAPACITY)?;

        // Test with width = 3

        // Proving
        let (i, o) = poseidon_sponge_params::<3>();
        let mut prover = Prover::new(b"sponge_tester");
        sponge_gadget_tester::<3>(&i, o, prover.mut_cs());
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verify
        let mut verifier = Verifier::new(b"sponge_tester");
        sponge_gadget_tester::<3>(&i, o, verifier.mut_cs());
        verifier.preprocess(&ck)?;
        verifier.verify(&proof, &vk, &vec![BlsScalar::zero()])
    }

    #[test]
    fn sponge_gadget_hades_width() -> Result<()> {
        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(CAPACITY, &mut rand::thread_rng())?;
        let (ck, vk) = public_parameters.trim(CAPACITY)?;

        // Test with width = 5

        // Proving
        let (i, o) = poseidon_sponge_params::<WIDTH>();
        let mut prover = Prover::new(b"sponge_tester");
        sponge_gadget_tester::<WIDTH>(&i, o, prover.mut_cs());
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verify
        let mut verifier = Verifier::new(b"sponge_tester");
        sponge_gadget_tester::<WIDTH>(&i, o, verifier.mut_cs());
        verifier.preprocess(&ck)?;
        verifier.verify(&proof, &vk, &vec![BlsScalar::zero()])
    }

    #[test]
    fn sponge_gadget_width_15() -> Result<()> {
        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng())?;
        let (ck, vk) = public_parameters.trim(1 << 17)?;

        // Test with width = 15

        // Proving
        let (i, o) = poseidon_sponge_params::<15>();
        let mut prover = Prover::new(b"sponge_tester");
        sponge_gadget_tester::<15>(&i, o, prover.mut_cs());
        prover.preprocess(&ck)?;
        let proof = prover.prove(&ck)?;

        // Verify
        let mut verifier = Verifier::new(b"sponge_tester");
        sponge_gadget_tester::<15>(&i, o, verifier.mut_cs());
        verifier.preprocess(&ck)?;
        verifier.verify(&proof, &vk, &vec![BlsScalar::zero()])
    }
}
