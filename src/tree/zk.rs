// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonBranch;
use dusk_hades::{GadgetStrategy, Strategy};
use dusk_plonk::prelude::*;

/// Perform a merkle opening for a given branch and return the calculated root
pub fn merkle_opening<const DEPTH: usize>(
    composer: &mut StandardComposer,
    branch: &PoseidonBranch<DEPTH>,
) -> Variable {
    // Generate and constraint zero.
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());
    let mut root = zero;

    // Generate a permutation container
    let mut perm = [zero; dusk_hades::WIDTH];

    // For every level, replace the level offset with needle,
    // permutate the level and set the needle to the next level
    // to the poseidon result of the permutation
    branch.as_ref().iter().for_each(|level| {
        // Create the bits representation of the offset as witness
        let offset_flag = level.offset_flag();
        let mut sum = zero;
        let mut offset_bits = [zero; dusk_hades::WIDTH - 1];
        offset_bits.iter_mut().fold(1, |mask, bit| {
            *bit = composer
                .add_input(BlsScalar::from((offset_flag & mask).min(1)));

            sum = composer.add(
                (BlsScalar::one(), sum),
                (BlsScalar::one(), *bit),
                BlsScalar::zero(),
                None,
            );

            mask << 1
        });
        composer.constrain_to_constant(sum, BlsScalar::one(), None);

        let leaf = composer.add_input(**level);
        level
            .as_ref()
            .iter()
            .zip(perm.iter_mut())
            .enumerate()
            .for_each(|(i, (l, p))| {
                *p = composer.add_input(*l);

                if i > 0 {
                    let b = offset_bits[i - 1];

                    let a = composer.mul(
                        BlsScalar::one(),
                        b,
                        *p,
                        BlsScalar::zero(),
                        None,
                    );

                    let b = composer.mul(
                        BlsScalar::one(),
                        b,
                        leaf,
                        BlsScalar::zero(),
                        None,
                    );

                    composer.assert_equal(a, b);
                }
            });

        root = perm[1];
        let mut h = GadgetStrategy::new(composer);
        h.perm(&mut perm);
    });

    root
}
