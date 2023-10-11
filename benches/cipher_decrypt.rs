// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_poseidon::cipher::{self, PoseidonCipher};

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_jubjub::GENERATOR;
use dusk_plonk::prelude::*;
use ff::Field;
use rand::rngs::StdRng;
use rand::SeedableRng;

use std::ops::Mul;

const CAPACITY: usize = 11;
const MESSAGE_CAPACITY: usize = 2;
const CIPHER_SIZE: usize = MESSAGE_CAPACITY + 1;

#[derive(Default)]
pub struct CipherDecrypt {
    shared: JubJubAffine,
    nonce: BlsScalar,
    cipher: PoseidonCipher,
}

impl CipherDecrypt {
    pub fn random(rng: &mut StdRng) -> Self {
        let shared =
            GENERATOR.to_niels().mul(&JubJubScalar::random(rng)).into();
        let nonce = BlsScalar::random(&mut *rng);
        let message =
            [BlsScalar::random(&mut *rng), BlsScalar::random(&mut *rng)];
        let cipher = PoseidonCipher::encrypt(&message, &shared, &nonce);

        Self {
            shared,
            nonce,
            cipher,
        }
    }
}

impl Circuit for CipherDecrypt {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        let shared = composer.append_point(self.shared);
        let nonce = composer.append_witness(self.nonce);

        let mut cipher_circuit = [C::ZERO; CIPHER_SIZE];
        self.cipher
            .cipher()
            .iter()
            .zip(cipher_circuit.iter_mut())
            .for_each(|(cipher_scalar, cipher_witness)| {
                *cipher_witness = composer.append_witness(*cipher_scalar);
            });

        cipher::decrypt(composer, &shared, nonce, &cipher_circuit);

        Ok(())
    }
}

// Benchmark cipher decryption
fn bench_cipher_decryption(c: &mut Criterion) {
    // Prepare benchmarks and initialize variables
    let label = b"cipher decryption benchmark";
    let mut rng = StdRng::seed_from_u64(0xc001);
    let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();
    let (prover, verifier) = Compiler::compile::<CipherDecrypt>(&pp, label)
        .expect("Circuit should compile successfully");
    let mut proof = Proof::default();
    let public_inputs = Vec::new();
    let circuit = CipherDecrypt::random(&mut rng);

    // Benchmark native cipher decryption
    c.bench_function("cipher decryption native", |b| {
        b.iter(|| {
            PoseidonCipher::decrypt(
                black_box(&circuit.cipher),
                black_box(&circuit.shared),
                black_box(&circuit.nonce),
            );
        })
    });

    // Benchmark proof creation
    c.bench_function("cipher decryption proof generation", |b| {
        b.iter(|| {
            (proof, _) = prover
                .prove(&mut rng, black_box(&circuit))
                .expect("Proof generation should succeed");
        })
    });

    // Benchmark proof verification
    c.bench_function("cipher decryption proof verification", |b| {
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
    targets = bench_cipher_decryption
}
criterion_main!(benches);
