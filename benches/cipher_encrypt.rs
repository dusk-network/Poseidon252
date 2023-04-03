// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_poseidon::cipher::{self, PoseidonCipher};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_jubjub::GENERATOR;
use dusk_plonk::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

use std::ops::Mul;

const CAPACITY: usize = 11;
const MESSAGE_CAPACITY: usize = 2;

#[derive(Default)]
pub struct CipherEncrypt {
    shared: JubJubAffine,
    nonce: BlsScalar,
    message: [BlsScalar; MESSAGE_CAPACITY],
}

impl CipherEncrypt {
    pub fn random(rng: &mut StdRng) -> Self {
        let shared =
            GENERATOR.to_niels().mul(&JubJubScalar::random(rng)).into();
        let nonce = BlsScalar::random(rng);
        let message = [BlsScalar::random(rng), BlsScalar::random(rng)];

        Self {
            shared,
            nonce,
            message,
        }
    }
}

impl Circuit for CipherEncrypt {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        let shared = composer.append_point(self.shared);
        let nonce = composer.append_witness(self.nonce);

        let mut message_circuit = [C::ZERO; MESSAGE_CAPACITY];
        self.message
            .iter()
            .zip(message_circuit.iter_mut())
            .for_each(|(message_scalar, message_witness)| {
                *message_witness = composer.append_witness(*message_scalar);
            });

        cipher::encrypt(composer, &shared, nonce, &message_circuit);

        Ok(())
    }
}

// Benchmark cipher encryption
fn bench_cipher_encryption(c: &mut Criterion) {
    // Prepare benchmarks and initialize variables
    let label = b"cipher encryption benchmark";
    let rng = &mut StdRng::seed_from_u64(0xc001);
    let pp = PublicParameters::setup(1 << CAPACITY, rng).unwrap();
    let (prover, verifier) = Compiler::compile::<CipherEncrypt>(&pp, label)
        .expect("Circuit should compile successfully");
    let mut proof = Proof::default();
    let public_inputs = Vec::new();
    let circuit = CipherEncrypt::random(rng);

    // Benchmark native cipher encryption
    c.bench_function("cipher encryption native", |b| {
        b.iter(|| {
            PoseidonCipher::encrypt(
                black_box(&circuit.message),
                black_box(&circuit.shared),
                black_box(&circuit.nonce),
            );
        })
    });

    // Benchmark proof creation
    c.bench_function("cipher encryption proof generation", |b| {
        b.iter(|| {
            (proof, _) = prover
                .prove(rng, black_box(&circuit))
                .expect("Proof generation should succeed");
        })
    });

    // Benchmark proof verification
    c.bench_function("cipher encryption proof verification", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(&proof), &public_inputs)
                .expect("Proof verification should succeed");
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_cipher_encryption
}
criterion_main!(benches);
