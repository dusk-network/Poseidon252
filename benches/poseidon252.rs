use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_plonk::prelude::*;
use kelvin::Blake2b;
use poseidon252::merkle_proof::merkle_opening_gadget;
use poseidon252::{
    PoseidonAnnotation, PoseidonBranch, PoseidonTree, StorageScalar,
};

fn merkle_opening(c: &mut Criterion) {
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

    let branch = ptree.get(515).unwrap().unwrap();

    let branch_prove = branch.clone();
    c.bench_function("merkle-opening-prove", |b| {
        let mut prover = Prover::new(b"merkle_opening_bench");
        let proven_leaf = prover.mut_cs().add_input(*branch_prove);
        merkle_opening_gadget(prover.mut_cs(), branch_prove, proven_leaf);
        prover.preprocess(&ck).unwrap();

        b.iter(|| {
            black_box(prover.prove(&ck).unwrap());
        })
    });

    let branch_verify = branch.clone();
    c.bench_function("merkle-opening-verify", |b| {
        let mut prover = Prover::new(b"merkle_opening_bench");
        let proven_leaf = prover.mut_cs().add_input(*branch_verify);
        merkle_opening_gadget(prover.mut_cs(), branch_verify, proven_leaf);
        prover.preprocess(&ck).unwrap();
        let proof = prover.prove(&ck).unwrap();
        let pi = prover.mut_cs().public_inputs;

        let mut verifier = Verifier::new(b"merkle_opening_bench");
        let proven_leaf = verifier.mut_cs().add_input(BlsScalar::zero());
        merkle_opening_gadget(
            verifier.mut_cs(),
            PoseidonBranch::mock(&[BlsScalar::zero()], depth),
            proven_leaf,
        );
        verifier.preprocess(&ck).unwrap();

        b.iter(|| {
            black_box(verifier.verify(&proof, &vk, pi.as_slice()).unwrap());
        })
    });
}

//criterion_group!(benches, merkle_opening);
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = merkle_opening
}
criterion_main!(benches);
