//! Merkle-tree hashing functions using Poseidon252
//!

use super::poseidon_branch::PoseidonBranch;
use crate::merkle_lvl_hash::hash::*;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::StandardComposer;
use hades252::WIDTH;

pub fn merkle_opening_gadget(composer: &mut StandardComposer, branch: PoseidonBranch) {
    // Allocate space for each level Variables that will be generated.
    let mut lvl_vars = [composer.zero_var; WIDTH];
    // Allocate space for the last level computed hash as a variable to compare
    // it against the root.
    let mut lvl_hash = composer.zero_var;

    // Start the tree-level hashing towards the root.
    //
    // On each level we will check that the hash of the whole level is indeed
    // the one that we expect.
    //
    // It is guaranteed that the `PoseidonBranch::PoseidonLevel` will come with `upper_lvl_hash` field
    // correctly set to the one that appears on the next upper level of the tree.
    for level in branch.levels {
        // Generate the Variables for the corresponding level.
        level
            .leaves
            .iter()
            .zip(lvl_vars.iter_mut())
            .for_each(|(leaf, var)| {
                *var = composer.add_input(*leaf);
            });
        // Hash the level & check against the previously-obtained lvl_hash which is
        // guaranteed to be in the upper level.
        lvl_hash = merkle_level_hash_gadget(composer, &lvl_vars);
        // Constraint the lvl hash to be the expected one that was pre-computed before during the
        // `PoseidonBranch` generation.
        //
        // We want to re-use the circuit so we need to set the upper level hashes that were
        // pre-computed on the `PoseidonBranch` generation as secret variables instead of
        // circuit descriptors.
        let upper_lvl_hash_var = composer.add_input(level.upper_lvl_hash);
        composer.add_gate(
            lvl_hash,
            upper_lvl_hash_var,
            composer.zero_var,
            -Scalar::one(),
            Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
        );
    }

    // It's one gate redundancy, but atm, we prefer to add another check regarding the last lvl-hash
    // agains the tree root which will be a Public Input. On this case, it is not possible to make any kind
    // of cheating on the Prover side by modifying the underlying `PoseidonBranch` data.
    composer.constrain_to_constant(lvl_hash, Scalar::zero(), -branch.root);
}
