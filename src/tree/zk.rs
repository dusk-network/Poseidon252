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
    leaf: Variable,
) -> Variable {
    // Generate and constraint zero.
    let zero = composer.add_witness_to_circuit_description(BlsScalar::zero());
    let mut root = zero;

    // Generate a permutation container
    let mut perm = [zero; dusk_hades::WIDTH];

    // For every level, replace the level offset with needle,
    // permutate the level and set the needle to the next level
    // to the poseidon result of the permutation
    branch.as_ref().iter().fold(leaf, |needle, level| {
        let offset = level.offset() as usize;

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

#[cfg(test)]
mod tests {
    use crate::tree::tests::MockLeaf;
    use crate::tree::{merkle_opening, PoseidonAnnotation, PoseidonTree};
    use anyhow::Result;
    use canonical_host::MemStore;
    use dusk_plonk::prelude::*;

    #[test]
    fn tree_merkle_opening() -> Result<()> {
        const DEPTH: usize = 17;

        let pub_params =
            PublicParameters::setup(1 << 15, &mut rand::thread_rng())?;
        let (ck, ok) = pub_params.trim(1 << 15)?;

        let mut tree: PoseidonTree<
            MockLeaf,
            PoseidonAnnotation,
            MemStore,
            DEPTH,
        > = PoseidonTree::new();

        for i in 0..1024 {
            let l = MockLeaf::from(i as u64);
            tree.push(l).unwrap();
        }

        let gadget_tester = |composer: &mut StandardComposer,
                             tree: &PoseidonTree<
            MockLeaf,
            PoseidonAnnotation,
            MemStore,
            DEPTH,
        >,
                             n: usize| {
            let branch = tree.branch(n).unwrap().unwrap();
            let root = tree.root().unwrap();

            let leaf = BlsScalar::from(n as u64);
            let leaf = composer.add_input(leaf);

            let root_p = merkle_opening::<DEPTH>(composer, &branch, leaf);
            composer.constrain_to_constant(root_p, BlsScalar::zero(), -root);
        };

        let label = b"opening_gadget";

        for i in [0, 567, 1023].iter() {
            let mut prover = Prover::new(label);
            gadget_tester(prover.mut_cs(), &tree, *i);
            prover.preprocess(&ck)?;
            let proof = prover.prove(&ck)?;

            let mut verifier = Verifier::new(label);
            gadget_tester(verifier.mut_cs(), &tree, *i);
            verifier.preprocess(&ck)?;
            let pi = verifier.mut_cs().public_inputs.clone();
            verifier.verify(&proof, &ok, &pi).unwrap();
        }

        Ok(())
    }
}
