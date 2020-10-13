use dusk_plonk::prelude::*;
use kelvin::Blake2b;
use poseidon252::merkle_proof::merkle_opening_gadget;
use poseidon252::{
    PoseidonAnnotation, PoseidonBranch, PoseidonTree, StorageScalar,
};

fn main() {
    let pub_params =
        PublicParameters::setup(1 << 15, &mut rand::thread_rng()).unwrap();
    let (ck, vk) = pub_params.trim(1 << 15).unwrap();

    let depth = 17;

    let mut ptree: PoseidonTree<_, PoseidonAnnotation, Blake2b> =
        PoseidonTree::new(depth);

    for i in 0..1024 {
        ptree
            .push(StorageScalar(BlsScalar::from(i as u64)))
            .unwrap();
    }

    let branch = ptree.get(1).unwrap().unwrap();

    let mut prover = Prover::new(b"merkle_opening_bench");
    let proven_leaf = prover.mut_cs().add_input(*branch);
    merkle_opening_gadget(prover.mut_cs(), branch, proven_leaf);
    prover.preprocess(&ck).unwrap();
    let proof = prover.prove(&ck).unwrap();
    let pi = prover.mut_cs().public_inputs.clone();

    let mut verifier = Verifier::new(b"merkle_opening_bench");
    let proven_leaf = verifier.mut_cs().add_input(BlsScalar::zero());
    merkle_opening_gadget(
        verifier.mut_cs(),
        PoseidonBranch::mock(&[BlsScalar::zero()], depth),
        proven_leaf,
    );
    verifier.preprocess(&ck).unwrap();
    verifier.verify(&proof, &vk, pi.as_slice()).unwrap();
}
