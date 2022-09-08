// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "canon")]

use core::borrow::Borrow;

use dusk_poseidon::sponge;
use dusk_poseidon::tree::{
    merkle_opening, PoseidonAnnotation, PoseidonBranch, PoseidonLeaf,
    PoseidonTree,
};

use canonical_derive::Canon;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_plonk::error::Error as PlonkError;
use dusk_plonk::prelude::*;
use microkelvin::Keyed;
use rand_core::{CryptoRng, OsRng, RngCore};

const DEPTH: usize = 17;
const CAPACITY: usize = 15;
type Tree = PoseidonTree<MockLeaf, PoseidonAnnotation, DEPTH>;

#[derive(
    Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon,
)]
pub struct MockLeaf {
    data: BlsScalar,
    pub pos: u64,
    pub expiration: u64,
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
        let expiration = rng.next_u64();

        Self {
            data,
            pos,
            expiration,
        }
    }
}

impl From<u64> for MockLeaf {
    fn from(n: u64) -> MockLeaf {
        MockLeaf {
            data: BlsScalar::from(n),
            pos: 0,
            expiration: n / 3,
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

impl Borrow<u64> for MockLeaf {
    fn borrow(&self) -> &u64 {
        // What does expiration stand for? We only use it for this trait
        &self.expiration
        // Could also use position
        // &self.pos
    }
}

struct MerkleOpeningCircuit {
    branch: PoseidonBranch<DEPTH>,
}

impl MerkleOpeningCircuit {
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        tree: &mut Tree,
    ) -> Self {
        let leaf = MockLeaf::random(rng);
        let pos = tree.push(leaf).expect("Tree should be appendable");

        let branch = tree
            .branch(pos)
            .expect("Tree should be possible to access at the given position")
            .expect("It should be possible to fetch the appended leaf");

        Self { branch }
    }
}

impl Circuit for MerkleOpeningCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        use std::ops::Deref;

        let leaf: BlsScalar = *self.branch.deref();
        let leaf = composer.append_witness(leaf);

        let root = self.branch.root();
        let root = composer.append_witness(*root);

        let root_p = merkle_opening::<DEPTH>(composer, &self.branch, leaf);

        composer.assert_equal(root_p, root);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << CAPACITY
    }
}

fn proof_creation<C>(
    circuit: &mut C,
    pp: &PublicParameters,
    pk: &ProverKey,
    label: &'static [u8],
) -> Proof
where
    C: Circuit,
{
    circuit
        .prove(pp, pk, label, &mut OsRng)
        .expect("Proof generation should pass")
}

fn bench_opening_proof(c: &mut Criterion) {
    let label = b"dusk-network";
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

    let mut tree = Tree::default();

    let mut circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);
    let (pk, vd) = circuit.compile(&pp).expect("Failed to compile circuit");

    let mut tree = Tree::default();
    let mut circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);
    let mut proof = Proof::default();
    c.bench_function("opening proof generation", |b| {
        b.iter(|| {
            proof = proof_creation(black_box(&mut circuit), &pp, &pk, label);
        })
    });

    c.bench_function("opening proof verification", |b| {
        b.iter(|| {
            MerkleOpeningCircuit::verify(
                &pp,
                &vd,
                black_box(&proof),
                &[],
                label,
            )
            .expect("Proof verification should pass");
        })
    });
}

struct LevelHash {
    // 5 = 4 (arity) + 1 (sponge capacity)
    level: [BlsScalar; 5],
    hash: BlsScalar,
}

impl Circuit for LevelHash {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        let mut level_witnesses = vec![];
        for scalar in self.level.iter() {
            level_witnesses.push(composer.append_witness(*scalar));
        }

        let calculated = sponge::gadget(composer, &level_witnesses);

        let expected = composer.append_witness(self.hash);
        composer.assert_equal(calculated, expected);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << CAPACITY
    }
}

impl LevelHash {
    pub fn random() -> Self {
        let input = [
            BlsScalar::from(1),
            BlsScalar::random(&mut OsRng),
            BlsScalar::random(&mut OsRng),
            BlsScalar::random(&mut OsRng),
            BlsScalar::random(&mut OsRng),
        ];
        LevelHash {
            level: input,
            hash: sponge::hash(&input),
        }
    }
}

fn bench_level_hash_proof(c: &mut Criterion) {
    let label = b"dusk-network";
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

    let mut circuit = LevelHash::random();
    let (pk, vd) = circuit.compile(&pp).expect("Failed to compile circuit");

    // sanity check:
    let mut circuit = LevelHash::random();
    let proof = proof_creation(&mut circuit, &pp, &pk, label);
    LevelHash::verify(&pp, &vd, &proof, &[], label)
        .expect("circuit should pass");

    let mut circuit = LevelHash::random();
    let mut proof = Proof::default();
    c.bench_function("hash merkle level proof creation", |b| {
        b.iter(|| {
            proof = proof_creation(black_box(&mut circuit), &pp, &pk, label)
        })
    });

    c.bench_function("hash merkle level proof verification", |b| {
        b.iter(|| {
            LevelHash::verify(&pp, &vd, black_box(&proof), &[], label)
                .expect("Proof verification should pass");
        })
    });
}

// criterion_group!(benches, bench_opening_proof, bench_level_hash_proof);
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_opening_proof, bench_level_hash_proof
}
criterion_main!(benches);
