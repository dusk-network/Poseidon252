// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonBranch;
use dusk_hades::GadgetStrategy;

use dusk_plonk::prelude::*;

/// Perform a merkle opening for a given branch and return the calculated root
pub fn merkle_opening<const DEPTH: usize>(
    composer: &mut TurboComposer,
    branch: &PoseidonBranch<DEPTH>,
    leaf: Witness,
) -> Witness {
    let zero = TurboComposer::constant_zero();

    let mut base = true;
    let mut root = zero;

    // Generate a permutation container
    let mut perm = [zero; dusk_hades::WIDTH];

    // For every level, replace the level offset with needle,
    // permute the level and set the needle to the next level
    // to the poseidon result of the permutation
    branch.as_ref().iter().for_each(|level| {
        // Create the bits representation of the offset as witness
        let offset_flag = level.offset_flag();

        let mut sum = zero;
        let mut offset_bits = [zero; dusk_hades::WIDTH - 1];
        offset_bits.iter_mut().fold(1, |mask, bit| {
            let b = BlsScalar::from((offset_flag & mask).min(1));
            *bit = composer.append_witness(b);

            let constraint = Constraint::new().left(1).a(sum).right(1).b(*bit);
            sum = composer.gate_add(constraint);

            mask << 1
        });

        composer.assert_equal_constant(sum, BlsScalar::one(), None);

        let needle = composer.append_witness(**level);
        if base {
            composer.assert_equal(leaf, needle);
            base = false;
        }

        level
            .as_ref()
            .iter()
            .zip(perm.iter_mut())
            .enumerate()
            .for_each(|(i, (l, p))| {
                *p = composer.append_witness(*l);

                if i > 0 {
                    let b = offset_bits[i - 1];

                    let constraint = Constraint::new().mult(1).a(b).b(*p);
                    let a = composer.gate_mul(constraint);

                    let constraint = Constraint::new().mult(1).a(b).b(needle);
                    let b = composer.gate_mul(constraint);

                    composer.assert_equal(a, b);
                }
            });

        root = perm[1];
        GadgetStrategy::gadget(composer, &mut perm);
    });

    root
}
