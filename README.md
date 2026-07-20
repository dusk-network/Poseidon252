![Build Status](https://github.com/dusk-network/Poseidon252/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-poseidon252-blueviolet)](https://github.com/dusk-network/Poseidon252)
[![Documentation](https://img.shields.io/badge/docs-poseidon252-blue)](https://docs.rs/dusk-poseidon/latest/dusk_poseidon/)

# Dusk-Poseidon

Reference implementation for the Poseidon Hashing algorithm.

Reference:
[Starkad and Poseidon: New Hash Functions for Zero Knowledge Proof Systems](https://eprint.iacr.org/2019/458.pdf)

This repository has been created so there's a unique library that holds the tools & functions required to perform Poseidon Hashes on field elements of the bls12-381 elliptic curve.

The hash uses the Hades design for its inner permutation and the [SAFE](https://eprint.iacr.org/2023/522.pdf) framework for contstructing the sponge.

The library provides the two hashing techniques of Poseidon:
- The 'normal' hashing functionalities operating on `BlsScalar`.
- The 'gadget' hashing functionalities that build a circuit which outputs the hash.

## Example

```rust
use rand::rngs::StdRng;
use rand::SeedableRng;

use dusk_poseidon::{Domain, Hash};
use dusk_bls12_381::BlsScalar;
use ff::Field;

// generate random input
let mut rng = StdRng::seed_from_u64(0xbeef);
let mut input = [BlsScalar::zero(); 42];
for scalar in input.iter_mut() {
    *scalar = BlsScalar::random(&mut rng);
}

// digest the input all at once
let hash = Hash::digest(Domain::Other, &input);

// update the input gradually
let mut hasher = Hash::new(Domain::Other);
hasher.update(&input[..3]);
hasher.update(&input[3..]);
assert_eq!(hash, hasher.finalize());

// create a hash used for merkle tree hashing with arity = 4
let merkle_hash = Hash::digest(Domain::Merkle4, &input[..4]);

// which is different when another domain is used
assert_ne!(merkle_hash, Hash::digest(Domain::Other, &input[..4]));
```

## Benchmarks

There are benchmarks for hashing, encrypting and decrypting in their native form, operating on `Scalar`, and for a zero-knowledge circuit proof generation and verification.

To run all benchmarks on your machine, run
```shell
cargo bench --features=zk,encryption
```
in the repository.

## Licensing

This code is licensed under Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for further info.

## About

Implementation designed by the [dusk](https://dusk.network) team.

## Contributing

- If you want to contribute to this repository/project please, check [CONTRIBUTING.md](https://github.com/dusk-network/Poseidon252/blob/master/CONTRIBUTING.md)
- If you want to report a bug or request a new feature addition, please open an issue on this repository.
