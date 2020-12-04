# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.0] - 04-12-20
### Fixed
- PoseidonMaxAnnotation borrow fix for latest microkelvin.

## [0.14.0] - 17-11-20
### Changed
- No-Std compatibility.

## [0.13.1] - 06-11-20
### Changed
- Feature split between `canon` and `canon_host` for constrained and unconstrained environments.
- Canon implementation for PoseidonTree.

## [0.13.0] - 04-11-20
### Changed
- PoseidonLeaf pos setter for API consistency with Phoenix

### Removed
- PoseidonCipher std::io implementations

## [0.12.0] - 03-11-20
### Added
- Gate-featured `canonical` impl.
- `PoseidonAnnotation` as generic to support walkable implementations

## [0.11.0] - 30-10-20
### Changed
- Bump `hades252` to `v0.10.0`
- Major refactor on the poseidon tree to comply with the simplifications provided by microkelvin

## [0.10.0] - 05-10-20
### Changed
- Bump `hades252` to `v0.9.0`
- Bump `dusk-plonk` to `v0.3.1`

## [0.9.0] - 04-10-20
### Added
- `root()` fn for `PoseidonBranch`.

### Changed
- Padding implementation for `PoseidonBranch` with opening gadgets.

### Removed
- Extension fn's from the crate.

## [0.8.1] - 01-10-20
### Changed
- Implement `inner` and `inner_mut` methods on PoseidonTree

## [0.8.0] - 29-09-20
### Changed
- Use `dusk-plonk` `v0.2.11`
- Use `hades252 0.8.0`

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
