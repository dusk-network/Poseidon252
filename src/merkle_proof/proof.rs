//! Merkle-tree hashing functions using Poseidon252
//!

use super::poseidon_branch::PoseidonBranch;
use crate::merkle_lvl_hash::hash::*;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::StandardComposer;
use hades252::WIDTH;

/// Provided a `PoseidonBranch`, and a `&mut StandardComposer`, print inside of the
/// constraint system a Merkle Tree Proof that hashes up from the searched leave in kelvin until
/// the root of the tree constraining each level hashed on the process.
///
/// NOTE: The root of the PoseidonBranch (root of the Merkle tree) will be set as Public Input so we
/// can re-use the circuits that rely on this gadget.
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
    // which points to the position of the next level where the hash of the actual level is stored.
    // So then we will add a constraint that checks equalty to chain up the whole hashing procedure.
    branch
        .levels
        .iter()
        // zip an iter over the same branch levels but that points to one level avobe
        // in respect of the actual level that we are hashing.
        // This is indeed used to check that the resulting hash is inside of the upper
        // level leaves so we can add a constraint.
        .zip(branch.levels.iter().skip(1))
        .for_each(|(level, upper_level)| {
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
            lvl_hash = merkle_level_hash_gadget_without_bitflags(composer, &mut lvl_vars);
            // Constraint the lvl hash to be the expected one that was pre-computed before during the
            // `PoseidonBranch` generation.
            //
            // We want to re-use the circuit so we need to set the upper level hashes that were
            // pre-computed on the `PoseidonBranch` generation as secret variables instead of
            // circuit descriptors.
            let upper_lvl_hash_var = composer.add_input(upper_level.leaves[level.upper_lvl_hash]);
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
        });

    // Add the last check regarding the last lvl-hash agains the tree root
    // which will be a Public Input. On this case, it is not possible to make any kind
    // of cheating on the Prover side by modifying the underlying `PoseidonBranch` data.
    composer.constrain_to_constant(lvl_hash, Scalar::zero(), -branch.root);
}

pub fn merkle_opening_scalar_verification(branch: PoseidonBranch, root: Scalar) -> bool {
    // Check that the root is indeed the one that we think
    if branch.root != root {
        return false;
    };
    // Allocate space for the last level computed hash as a variable to compare
    // it against the root.
    let mut lvl_hash = Scalar::zero();

    // Define a flag to catch errors inside of the tree-hashing chain.
    let mut chain_err = false;

    // Start the tree-level hashing towards the root.
    //
    // On each level we will check that the hash of the whole level is indeed
    // the one that we expect.
    //
    // It is guaranteed that the `PoseidonBranch::PoseidonLevel` will come with `upper_lvl_hash` field
    // which points to the position of the next level where the hash of the actual level is stored.
    // So then we will add a constraint that checks equalty to chain up the whole hashing procedure.
    branch
        .levels
        .iter()
        // zip an iter over the same branch levels but that points to one level avobe
        // in respect of the actual level that we are hashing.
        // This is indeed used to check that the resulting hash is inside of the upper
        // level leaves so we can add a constraint.
        .zip(branch.levels.iter().skip(1))
        .for_each(|(level, upper_level)| {
            // Hash the level & check against the previously-obtained lvl_hash which is
            // guaranteed to be in the upper level.
            lvl_hash = merkle_level_hash_without_bitflags(&level);
            // Constraint the lvl hash to be the expected one that was pre-computed before during the
            // `PoseidonBranch` generation.
            //
            if lvl_hash != upper_level.leaves[level.upper_lvl_hash] {
                chain_err = true;
            };
        });

    // Add the last check regarding the last lvl-hash against the tree root.
    if (lvl_hash != branch.root) | chain_err {
        return false;
    };
    true
}
