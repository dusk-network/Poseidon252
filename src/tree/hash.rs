// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use hades252::strategies::{ScalarStrategy, Strategy};

/// Perform the Hades252 permutation
pub fn permutate(input: &mut [BlsScalar; hades252::WIDTH]) -> BlsScalar {
    ScalarStrategy::new().perm(input);

    input[1]
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use dusk_bls12_381::BlsScalar;

    use crate::merkle::hash_gadget;
    use anyhow::Result;
    use dusk_plonk::prelude::*;

    #[test]
    fn merkle_preimage() -> Result<()> {
        const CAPACITY: usize = 1 << 10;

        let pub_params =
            PublicParameters::setup(CAPACITY, &mut rand::thread_rng())?;
        let (ck, ok) = pub_params.trim(CAPACITY)?;

        let label = b"merkle_hash_gadget";
        fn execute(
            label: &'static [u8],
            ck: &CommitKey,
            ok: &OpeningKey,
            input: &[BlsScalar],
        ) -> Result<()> {
            let gadget_tester =
                |composer: &mut StandardComposer, input: &[BlsScalar]| {
                    let hash = hash(input);
                    let hash_p = hash_gadget(composer, input);

                    composer.constrain_to_constant(
                        hash_p,
                        BlsScalar::zero(),
                        -hash,
                    );
                };

            let mut prover = Prover::new(label);
            gadget_tester(prover.mut_cs(), &input);
            prover.preprocess(ck)?;
            let proof = prover.prove(ck)?;

            let mut verifier = Verifier::new(label);
            gadget_tester(verifier.mut_cs(), &input);
            verifier.preprocess(ck)?;
            let pi = verifier.mut_cs().public_inputs.clone();
            verifier.verify(&proof, ok, &pi).unwrap();

            Ok(())
        }

        execute(label, &ck, &ok, &[])?;
        execute(label, &ck, &ok, &[BlsScalar::from(25)])?;
        execute(
            label,
            &ck,
            &ok,
            &[BlsScalar::from(54), BlsScalar::from(43728)],
        )?;
        execute(
            label,
            &ck,
            &ok,
            &[
                BlsScalar::from(54),
                BlsScalar::from(43728),
                BlsScalar::from(123),
            ],
        )?;
        execute(
            label,
            &ck,
            &ok,
            &[
                BlsScalar::from(54),
                BlsScalar::from(43728),
                BlsScalar::from(5846),
                BlsScalar::from(9834),
            ],
        )?;
        execute(
            label,
            &ck,
            &ok,
            &[
                BlsScalar::from(54),
                BlsScalar::from(43728),
                BlsScalar::from(5846),
                BlsScalar::from(9834),
                BlsScalar::from(23984),
            ],
        )?;

        Ok(())
    }
}
