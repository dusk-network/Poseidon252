//! Merkle-tree hashing functions using Poseidon252
//!
use super::poseidon_branch::PoseidonBranch;
use crate::merkle_lvl_hash::hash::*;

use dusk_plonk::prelude::*;
use hades252::WIDTH;

/// Provided a `kelvin::Branch`, a `&mut StandardComposer`, a leaf value and a root, print inside of the
/// constraint system a Merkle Tree Proof that hashes up from the searched leaf in kelvin until
/// the root of the tree constraining each level hashed on the process.
///
/// `branch_length` controls how much padding should be added to the branch to make it the correct length.
///
/// NOTE: The root of the `Branch` (root of the Merkle tree) will be set as Public Input so we
/// can re-use the circuits that rely on this gadget.
pub fn merkle_opening_gadget(
    composer: &mut StandardComposer,
    branch: PoseidonBranch,
    proven_leaf: Variable,
    proven_root: BlsScalar,
) {
    // Generate and constraint zero.
    let zero = composer.add_input(BlsScalar::zero());
    composer.constrain_to_constant(zero, BlsScalar::zero(), BlsScalar::zero());
    // Allocate space for each level Variables that will be generated.
    let mut lvl_vars = [zero; WIDTH];
    // Allocate space for the last level computed hash as a variable to compare
    // it against the root.
    let mut prev_lvl_hash: Variable;

    // Start the tree-level hashing towards the root.
    //
    // On each level we will check that the hash of the whole level is indeed
    // the one that we expect.
    //
    // It is guaranteed that the `PoseidonBranch::PoseidonLevel` will come with `offset` field
    // which points to the position of the level where the hash of the previous level is stored.
    //
    // In the case of the base of the tree, offset points to the leaf we're proving it's inclusion.
    // For this reason, we will hash the bottom level before we start the hashing chain to check
    // that the `Scalar` we're proving the inclusion of is indeed the one we expect and then, we
    // will store the first `lvl_hash` value.
    let bottom_lvl = branch.levels.first().unwrap();
    // Set lvl_vars = bottom level leaves as variables.
    // We're basically loading the level leaves into the composer and the lvl_vars array.
    bottom_lvl
        .leaves
        .iter()
        .zip(lvl_vars.iter_mut())
        .for_each(|(leaf, var)| *var = composer.add_input(*leaf));
    // Check that the leaf we've searched for is indeed the one specified in the bottom level offset.
    composer.assert_equal(lvl_vars[bottom_lvl.offset], proven_leaf);
    // Store in lvl_hash the hash of this bottom level.
    prev_lvl_hash =
        merkle_level_hash_gadget_without_bitflags(composer, &mut lvl_vars);

    branch.levels.iter().skip(1).for_each(|level| {
        // Generate the Variables for the corresponding level.
        level
            .leaves
            .iter()
            .zip(lvl_vars.iter_mut())
            // Load new level leaves as `Variable` inside the lvl_vars array.
            .for_each(|(leaf, var)| {
                *var = composer.add_input(*leaf);
            });
        // Check that the previous hash indeed corresponds to the leaf specified in this
        // level as `offset`.
        // We want to re-use the circuit so we need to set the level hashes that were
        // pre-computed on the `PoseidonBranch` generation as secret variables instead of
        // circuit descriptors.
        composer.add_gate(
            prev_lvl_hash,
            lvl_vars[level.offset],
            zero,
            -BlsScalar::one(),
            BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );
        // Hash the level & store it in prev_lvl_hash which should be in the upper
        // level if the proof is consistent.
        prev_lvl_hash =
            merkle_level_hash_gadget_without_bitflags(composer, &mut lvl_vars);
    });

    // Add the last check regarding the last lvl-hash agains the tree root
    // which will be a Public Input. On this case, it is not possible to make any kind
    // of cheating on the Prover side by modifying the underlying `PoseidonBranch` data.
    composer.constrain_to_constant(prev_lvl_hash, BlsScalar::zero(), -proven_root);

    assert_eq!(branch.root, proven_root);
}

/// Provided a `PoseidonBranch` and a Merkle Tree root, verify that
/// the path to the root is correct.
///
/// `branch_length` controls how much padding should be added to the branch to make it the correct length.
///
/// This hashing-chain is performed using Poseidon hashing algorithm
/// and relies on the `Hades252` permutation.
pub fn merkle_opening_scalar_verification(
    branch: PoseidonBranch,
    root: BlsScalar,
    leaf: BlsScalar,
) -> bool {
    // Check that the root is indeed the one that we think
    if branch.root != root {
        return false;
    };
    // Allocate space for the last level computed hash as a variable to compare
    // it against the root.
    let mut lvl_hash: BlsScalar;

    // Define a flag to catch errors inside of the tree-hashing chain.
    let mut chain_err = false;

    // Start the tree-level hashing towards the root.
    //
    // On each level we will check that the hash of the whole level is indeed
    // the one that we expect.
    //
    // It is guaranteed that the `PoseidonBranch::PoseidonLevel` will come with `offset` field
    // which points to the position of the level where the hash of the previous level is stored.
    //
    // In the case of the base of the tree, offset points to the leaf we're proving it's inclusion.
    // For this reason, we will hash the bottom level before we start the hashing chain to check
    // that the `Scalar` we're proving the inclusion of is indeed the one we expect and then, we
    // will store the first `lvl_hash` value.
    let bottom_lvl = branch.levels.first().unwrap();
    lvl_hash = merkle_level_hash_without_bitflags(&bottom_lvl);
    assert!(bottom_lvl.leaves[bottom_lvl.offset] == leaf);

    // Start the hashing chain towards the root skipping the first hash that we already computed.
    branch.levels.iter().skip(1).for_each(|level| {
        // Check that the hash of the downwards level is present in the level avobe (the actual one).
        if lvl_hash != level.leaves[level.offset] {
            chain_err = true;
        };
        // Hash the level & store it to then constrain it to be equal to the leaf at the offset position
        // of the upper level.
        lvl_hash = merkle_level_hash_without_bitflags(&level);
    });

    // Add the last check regarding the last lvl-hash against the tree root.
    if (lvl_hash != branch.root) | chain_err {
        return false;
    };
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing_utils::scalar_storage::StorageScalar;
    use crate::PoseidonTree;
    use kelvin::Blake2b;

    #[test]
    fn scalar_merkle_proof() {
        // Generate a tree with random scalars inside.
        let mut ptree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17);
        for i in 0..1024u64 {
            ptree
                .push(StorageScalar(BlsScalar::from(i as u64)))
                .unwrap();
        }

        for i in 0..1024u64 {
            // We want to proof that we know the Scalar tied to the key Xusize
            // and that indeed, it is inside the merkle tree.

            // In this case, the key X corresponds to the Scalar(X).
            // We're supposing that we're provided with a Kelvin::Branch to perform
            // the proof.
            let branch = ptree.poseidon_branch(i).unwrap().unwrap();

            // Get tree root.
            let root = ptree.root().unwrap();

            assert!(merkle_opening_scalar_verification(
                branch,
                root,
                BlsScalar::from(i),
            ));
        }
    }

    #[test]
    fn zero_knowledge_merkle_proof() {
        // Generate Composer & Public Parameters
        let pub_params =
            PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 16).unwrap();
        // Generate a tree with random scalars inside.
        let mut ptree: PoseidonTree<_, Blake2b> = PoseidonTree::new(17);
        for i in 0..1024u64 {
            ptree
                .push(StorageScalar(BlsScalar::from(i as u64)))
                .unwrap();
        }

        let mut composer_sizes = vec![];

        for i in [0u64, 567, 1023].iter() {
            let mut gadget_tester = |composer: &mut StandardComposer| {
                // We want to proof that we know the Scalar tied to the key Xusize
                // and that indeed, it is inside the merkle tree.

                // In this case, the key X corresponds to the Scalar(X).
                // We're supposing that we're provided with a Kelvin::Branch to perform
                // the proof.
                let branch = ptree.poseidon_branch(*i).unwrap().unwrap();

                // Get tree root.
                let root = ptree.root().unwrap();

                // Add the proven leaf value to the Constraint System
                let proven_leaf = composer.add_input(BlsScalar::from(*i));

                merkle_opening_gadget(composer, branch, proven_leaf, root);

                // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
                // to zero polynomials.
                composer.add_dummy_constraints();
                composer_sizes.push(composer.circuit_size());
            };

            // Proving
            let mut prover = Prover::new(b"merkle_opening_tester");
            gadget_tester(prover.mut_cs());
            prover.preprocess(&ck).expect("Error on preprocessing");
            let proof = prover.prove(&ck).expect("Error on proving");

            // Verify
            let mut verifier = Verifier::new(b"merkle_opening_tester");
            gadget_tester(verifier.mut_cs());
            verifier.preprocess(&ck).expect("Error on preprocessing");
            let pi = verifier.mut_cs().public_inputs.clone();
            assert!(verifier
                .verify(&proof, &vk, &pi)
                .is_ok());
        }

        // Assert that all the proofs are of the same size
        composer_sizes.dedup();
        assert_eq!(composer_sizes.len(), 1)
    }
}
