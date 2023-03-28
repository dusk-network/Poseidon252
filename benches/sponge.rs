// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dusk_hades::WIDTH;
use dusk_plonk::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

const CAPACITY: usize = 11;

#[derive(Default)]
struct SpongeCircuit {
    message: [BlsScalar; WIDTH],
}

impl SpongeCircuit {
    pub fn new(message: [BlsScalar; WIDTH]) -> Self {
        SpongeCircuit { message }
    }
}

impl Circuit for SpongeCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        let mut w_message = [C::ZERO; WIDTH];
        w_message
            .iter_mut()
            .zip(self.message)
            .for_each(|(witness, scalar)| {
                *witness = composer.append_witness(scalar);
            });

        dusk_poseidon::sponge::gadget(composer, &w_message);

        Ok(())
    }
}

// Benchmark for running sponge on 5 BlsScalar, one permutation
fn bench_sponge(c: &mut Criterion) {
    // Prepare benchmarks and initialize variables
    let label = b"sponge benchmark";
    let rng = &mut StdRng::seed_from_u64(0xc10d);
    let pp = PublicParameters::setup(1 << CAPACITY, rng).unwrap();
    let (prover, verifier) = Compiler::compile::<SpongeCircuit>(&pp, label)
        .expect("Circuit should compile successfully");
    let mut proof = Proof::default();
    let public_inputs = Vec::new();
    let message = [
        BlsScalar::random(rng),
        BlsScalar::random(rng),
        BlsScalar::random(rng),
        BlsScalar::random(rng),
        BlsScalar::random(rng),
    ];
    let circuit = SpongeCircuit::new(message);

    // Benchmark sponge native
    c.bench_function("sponge native", |b| {
        b.iter(|| {
            dusk_poseidon::sponge::hash(black_box(&circuit.message));
        })
    });

    // Benchmark circuit compilation
    c.bench_function("sponge circuit compilation", |b| {
        b.iter(|| {
            Compiler::compile::<SpongeCircuit>(black_box(&pp), label)
                .expect("Circuit should compile");
        })
    });

    // Benchmark proof creation
    c.bench_function("sponge proof generation", |b| {
        b.iter(|| {
            (proof, _) = prover
                .prove(rng, black_box(&circuit))
                .expect("Proof generation should succeed");
        })
    });

    // Benchmark proof verification
    c.bench_function("sponge proof verification", |b| {
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
    targets = bench_sponge
}
criterion_main!(benches);
