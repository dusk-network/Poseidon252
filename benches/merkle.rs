// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

use dusk_poseidon::tree::{self, PoseidonBranch, PoseidonLeaf, PoseidonTree};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_plonk::error::Error as PlonkError;
use dusk_plonk::prelude::*;
use nstack::annotation::Keyed;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

const DEPTH: usize = 17;
const CAPACITY: usize = 15;
type Tree = PoseidonTree<MockLeaf, u64, DEPTH>;

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct MockLeaf {
    data: BlsScalar,
    pub pos: u64,
}

impl Keyed<u64> for MockLeaf {
    fn key(&self) -> &u64 {
        &self.pos
    }
}

impl MockLeaf {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let data = BlsScalar::random(rng);
        let pos = 0;

        Self { data, pos }
    }
}

impl From<u64> for MockLeaf {
    fn from(n: u64) -> MockLeaf {
        MockLeaf {
            data: BlsScalar::from(n),
            pos: 0,
        }
    }
}

impl PoseidonLeaf for MockLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        self.data
    }

    fn pos(&self) -> &u64 {
        &self.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

#[derive(Default)]
struct MerkleOpeningCircuit {
    branch: PoseidonBranch<DEPTH>,
}

impl MerkleOpeningCircuit {
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        tree: &mut Tree,
    ) -> Self {
        let leaf = MockLeaf::random(rng);
        let pos = tree.push(leaf);

        let branch = tree.branch(pos).expect(
            "Tree should be possible to access at an existing position",
        );

        Self { branch }
    }
}

impl Circuit for MerkleOpeningCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), PlonkError>
    where
        C: Composer,
    {
        use std::ops::Deref;

        let leaf: BlsScalar = *self.branch.deref();
        let leaf = composer.append_witness(leaf);

        let root = self.branch.root();
        let root = composer.append_witness(*root);

        let root_p =
            tree::merkle_opening::<C, DEPTH>(composer, &self.branch, leaf);

        composer.assert_equal(root_p, root);

        Ok(())
    }
}

fn bench_opening_proof(c: &mut Criterion) {
    // Benchmark circuit compilation
    let label = b"dusk-network";
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();
    c.bench_function("Opening circuit compilation", |b| {
        b.iter(|| {
            Compiler::compile::<MerkleOpeningCircuit>(black_box(&pp), label)
                .expect("Circuit should compile");
        })
    });

    // Generate prover and verifier for the upcomming benchmarks
    let (prover, verifier) =
        Compiler::compile::<MerkleOpeningCircuit>(&pp, label)
            .expect("Circuit should compile successfully");

    // Benchmark proof creation
    let mut tree = Tree::default();
    let circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);
    let mut proof = Proof::default();
    let mut public_inputs = Vec::new();
    c.bench_function("opening proof generation", |b| {
        b.iter(|| {
            (proof, public_inputs) = prover
                .prove(&mut OsRng, black_box(&circuit))
                .expect("Proof generation should succeed");
        })
    });

    // Benchmark proof verification
    c.bench_function("opening proof verification", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(&proof), &public_inputs)
                .expect("Proof verification should succeed");
        })
    });
}

// criterion_group!(benches, bench_opening_proof, bench_level_hash_proof);
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_opening_proof
}
criterion_main!(benches);
