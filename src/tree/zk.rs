// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use super::PoseidonBranch;
use dusk_plonk::prelude::*;
use hades252::{GadgetStrategy, Strategy};

/// Perform a merkle opening for a given branch and return the calculated root
pub fn merkle_opening<const DEPTH: usize>(
    composer: &mut StandardComposer,
    branch: &PoseidonBranch<DEPTH>,
    leaf: Variable,
) -> Variable {
    // Generate and constraint zero.
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());
    let mut root = zero;

    // Generate a permutation container
    let mut perm = [zero; hades252::WIDTH];

    // For every level, replace the level offset with needle,
    // permutate the level and set the needle to the next level
    // to the poseidon result of the permutation
    branch.as_ref().iter().fold(leaf, |needle, level| {
        let offset = level.offset();

        level.as_ref().iter().enumerate().for_each(|(i, l)| {
            if i != offset {
                perm[i] = composer.add_input(*l);
            }
        });

        root = perm[1];
        perm[offset] = needle;

        let mut h = GadgetStrategy::new(composer);
        h.perm(&mut perm);
        perm[1]
    });

    root
}
