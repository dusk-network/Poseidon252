// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::hint::black_box;
use std::sync::LazyLock;

use criterion::{Criterion, criterion_group, criterion_main};
#[cfg(feature = "encryption")]
use dusk_jubjub::{GENERATOR_EXTENDED, JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, HADES_WIDTH, Hash, HashGadget};
#[cfg(feature = "encryption")]
use dusk_poseidon::{decrypt, decrypt_gadget, encrypt, encrypt_gadget};
use ff::Field;
use rand::SeedableRng;
use rand::rngs::StdRng;

const CAPACITY: usize = 11;

static PUB_PARAMS: LazyLock<PublicParameters> = LazyLock::new(|| {
    let mut rng = StdRng::seed_from_u64(0xfab);
    PublicParameters::setup(1 << CAPACITY, &mut rng)
        .expect("Setup of public params should pass")
});

#[derive(Default)]
struct SpongeCircuit {
    message: [BlsScalar; HADES_WIDTH - 1],
    output: BlsScalar,
}

impl SpongeCircuit {
    fn new(message: [BlsScalar; HADES_WIDTH - 1], output: BlsScalar) -> Self {
        Self { message, output }
    }
}

impl Circuit for SpongeCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let mut w_message = [Composer::ZERO; HADES_WIDTH - 1];
        w_message
            .iter_mut()
            .zip(self.message)
            .for_each(|(witness, scalar)| {
                *witness = composer.append_witness(scalar);
            });

        let output_witness =
            HashGadget::digest(composer, Domain::Merkle4, &w_message);
        composer.assert_equal_constant(output_witness[0], 0, Some(self.output));

        Ok(())
    }
}

fn bench_sponge(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xc10d);
    let (prover, verifier) =
        Compiler::compile::<SpongeCircuit>(&PUB_PARAMS, b"sponge benchmark")
            .expect("Circuit should compile successfully");
    let mut proof = Proof::default();
    let message = [
        BlsScalar::random(&mut rng),
        BlsScalar::random(&mut rng),
        BlsScalar::random(&mut rng),
        BlsScalar::random(&mut rng),
    ];
    let public_inputs = Hash::digest(Domain::Merkle4, &message);
    let circuit = SpongeCircuit::new(message, public_inputs[0]);

    c.bench_function("hash 4 BlsScalar", |b| {
        b.iter(|| {
            let _ = Hash::digest(Domain::Merkle4, black_box(&circuit.message));
        })
    });

    c.bench_function("hash 4 BlsScalar proof generation", |b| {
        b.iter(|| {
            (proof, _) = prover
                .prove(&mut rng, black_box(&circuit))
                .expect("Proof generation should succeed");
        })
    });

    c.bench_function("hash 4 BlsScalar proof verification", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(&proof), &public_inputs)
                .expect("Proof verification should succeed");
        })
    });
}

#[cfg(feature = "encryption")]
const MESSAGE_LEN: usize = 2;

#[cfg(feature = "encryption")]
fn random_inputs(
    rng: &mut StdRng,
) -> ([BlsScalar; MESSAGE_LEN], JubJubAffine, BlsScalar) {
    let mut message = [BlsScalar::zero(); MESSAGE_LEN];
    message
        .iter_mut()
        .for_each(|scalar| *scalar = BlsScalar::random(&mut *rng));
    let shared_secret =
        (GENERATOR_EXTENDED * &JubJubScalar::random(&mut *rng)).into();
    let nonce = BlsScalar::random(rng);
    (message, shared_secret, nonce)
}

#[cfg(feature = "encryption")]
#[derive(Debug)]
struct EncryptionCircuit {
    message: [BlsScalar; MESSAGE_LEN],
    shared_secret: JubJubAffine,
    nonce: BlsScalar,
}

#[cfg(feature = "encryption")]
impl EncryptionCircuit {
    fn random(rng: &mut StdRng) -> Self {
        let (message, shared_secret, nonce) = random_inputs(rng);
        Self {
            message,
            shared_secret,
            nonce,
        }
    }
}

#[cfg(feature = "encryption")]
impl Default for EncryptionCircuit {
    fn default() -> Self {
        Self {
            message: [BlsScalar::zero(); MESSAGE_LEN],
            shared_secret: JubJubAffine::identity(),
            nonce: BlsScalar::zero(),
        }
    }
}

#[cfg(feature = "encryption")]
impl Circuit for EncryptionCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let mut message_wit = [Composer::ZERO; MESSAGE_LEN];
        message_wit.iter_mut().zip(self.message).for_each(
            |(witness, message)| {
                *witness = composer.append_witness(message);
            },
        );
        let secret_wit = composer.append_point(self.shared_secret);
        let nonce_wit = composer.append_witness(self.nonce);

        let _cipher_result =
            encrypt_gadget(composer, &message_wit, &secret_wit, &nonce_wit)
                .expect("encryption should pass");

        Ok(())
    }
}

#[cfg(feature = "encryption")]
fn bench_encryption(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let (prover, verifier) = Compiler::compile::<EncryptionCircuit>(
        &PUB_PARAMS,
        b"hash-gadget-tester",
    )
    .expect("compilation should pass");
    let circuit = EncryptionCircuit::random(&mut rng);
    let public_inputs = Vec::new();
    let mut proof = Proof::default();

    c.bench_function("encrypt 2 BlsScalar", |b| {
        b.iter(|| {
            let _ = encrypt(
                black_box(&circuit.message),
                black_box(&circuit.shared_secret),
                black_box(&circuit.nonce),
            );
        })
    });

    c.bench_function("encrypt 2 BlsScalar proof generation", |b| {
        b.iter(|| {
            (proof, _) = prover
                .prove(&mut rng, black_box(&circuit))
                .expect("Proof generation should succeed");
        })
    });

    c.bench_function("encrypt 2 BlsScalar proof verification", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(&proof), &public_inputs)
                .expect("Proof verification should succeed");
        })
    });
}

#[cfg(feature = "encryption")]
#[derive(Debug)]
struct DecryptionCircuit {
    cipher: Vec<BlsScalar>,
    shared_secret: JubJubAffine,
    nonce: BlsScalar,
}

#[cfg(feature = "encryption")]
impl DecryptionCircuit {
    fn random(rng: &mut StdRng) -> Self {
        let (message, shared_secret, nonce) = random_inputs(rng);
        let cipher = encrypt(&message, &shared_secret, &nonce)
            .expect("encryption should not fail");
        Self {
            cipher,
            shared_secret,
            nonce,
        }
    }
}

#[cfg(feature = "encryption")]
impl Default for DecryptionCircuit {
    fn default() -> Self {
        Self {
            cipher: vec![BlsScalar::zero(); MESSAGE_LEN + 1],
            shared_secret: JubJubAffine::identity(),
            nonce: BlsScalar::zero(),
        }
    }
}

#[cfg(feature = "encryption")]
impl Circuit for DecryptionCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        let cipher_wit: Vec<_> = self
            .cipher
            .iter()
            .map(|cipher| composer.append_witness(*cipher))
            .collect();
        let secret_wit = composer.append_point(self.shared_secret);
        let nonce_wit = composer.append_witness(self.nonce);

        let _message_result =
            decrypt_gadget(composer, &cipher_wit, &secret_wit, &nonce_wit)
                .expect("decryption should pass");

        Ok(())
    }
}

#[cfg(feature = "encryption")]
fn bench_decryption(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x42424242);
    let (prover, verifier) = Compiler::compile::<DecryptionCircuit>(
        &PUB_PARAMS,
        b"hash-gadget-tester",
    )
    .expect("compilation should pass");
    let circuit = DecryptionCircuit::random(&mut rng);
    let public_inputs = Vec::new();
    let mut proof = Proof::default();

    c.bench_function("decrypt 2 BlsScalar", |b| {
        b.iter(|| {
            let _ = decrypt(
                black_box(&circuit.cipher),
                black_box(&circuit.shared_secret),
                black_box(&circuit.nonce),
            );
        })
    });

    c.bench_function("decrypt 2 BlsScalar proof generation", |b| {
        b.iter(|| {
            (proof, _) = prover
                .prove(&mut rng, black_box(&circuit))
                .expect("Proof generation should succeed");
        })
    });

    c.bench_function("decrypt 2 BlsScalar proof verification", |b| {
        b.iter(|| {
            verifier
                .verify(black_box(&proof), &public_inputs)
                .expect("Proof verification should succeed");
        })
    });
}

#[cfg(feature = "encryption")]
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sponge, bench_encryption, bench_decryption
}
#[cfg(not(feature = "encryption"))]
criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_sponge
}
criterion_main!(benches);
