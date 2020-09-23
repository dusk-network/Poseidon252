# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 23-09-20
### Changed
- Removed PI constraint from `merkle_opening_gadget` to implement
`CircuitBuilder` trait.
- Use `nstack 0.5.0`


## [0.6.4] - 07-09-20
### Added
- `PoseidonCipher` from/to bytes.

## [0.6.3] - 01-09-20
### Added
- Fixed_len hashing tools with variable input and output scalars.

## [0.6.2] - 27-08-20
### Added
- `PoseidonCipher` zk encrypt and decrypt functions.

## [0.6.1] - 13-08-20
### Changed
- `add_constant_witness` method replacement by `add_witness_to_circuit_description`.
- Changed `dusk-plonk` version to `v0.2.7`.
- Changed `Hades252` version to `v0.7.0`.

## [0.6.0] - 07-08-20
### Changed
- Use `dusk-plonk v0.2.0` as dependency.
- Refactor the tests related to Proof generation to work with the Prover&Verifier abstraction.

### Fixed
- Constrain `eom` in sponge_hash function.

### Added
- Poseidon cipher encryption, decryption and plonk gadget for zk prove of encryption with a key.


## [0.5.0] - 07-07-20
### Added

- `PoseidonTree` abstraction with padding and Proof gen. capabilities.


## [0.4.0] - 30-06-20
### Changed

- Use NarrowHAMT for ctsize Proofs & padded Branches instead of NStack.

### Removed

- NStack dependencies are no longer needed nor used.


## [0.3.0] - 23-06-20
### Added

- Merkle-Tree Opening inclusion proof generation capabilities.

- Methods for generating ZKProofs with PLONK
getting a kelvin::Branch.

- Use Nstack for merkle-tree branch type.


## [0.2.0] - 15-06-20
### Added

- PLONK as ZKP algorithm for the poseidon-hash
functions.

- Optimization on the Sponge hash fn to skip useless addition if the width of the messages is the appropiate one to do it. (WIDTH < HADES_WIDTH -1).

### Changed
- Both the merkle-hash and the sponge-hash techniqes use now PLONK instead of Bulletproofs.

### Removed
- Bulletproofs and Curve25519 as dependencies since we no longer use them.


## [0.1.0] - 10-02-20
### Added

- Poseidon252 Sponge-hash impl with BulletProofs.
- Variants of sponge for `Scalar` & `Gadget(Variable/LC)`.
