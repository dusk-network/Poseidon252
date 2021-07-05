# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add integration tests with examples of custom walker iterators [#134](https://github.com/dusk-network/poseidon252/issues/134)
- Add `persistance` feature to the crate [#151](https://github.com/dusk-network/poseidon252/issues/151)
- Add `truncated` module in sponge to deal with scalar conversions [#153](https://github.com/dusk-network/poseidon252/issues/153)

### Changed

- Change the tree logic to be compatible with `microkelvin v0.9` [#151](https://github.com/dusk-network/poseidon252/issues/151)
- Changed toolchain-file version to nightly-2021-06-06 [#149](https://github.com/dusk-network/poseidon252/issues/149)
- Change featureset config for the crate [#138](https://github.com/dusk-network/poseidon252/issues/138)
- Update `error` module to be no_std compatible [#132](https://github.com/dusk-network/poseidon252/issues/132)
- Update to latest `dusk-poseidon`, `dusk-bls12_381` and `dusk-jubjub` [#126](https://github.com/dusk-network/poseidon252/issues/126)
- Update to latest `microkelvin v0.9`, `nstack v0.9` and `canonical v0.6` [#125](https://github.com/dusk-network/poseidon252/issues/125)
- Update randomness provider to `rand_core` [#127](https://github.com/dusk-network/poseidon252/issues/127)
- Change trait bound system for `PoseidonTree` [#125](https://github.com/dusk-network/poseidon252/issues/125)
- Update `PoseidonTreeAnnotation` to be an autotrait [#125](https://github.com/dusk-network/poseidon252/issues/125)
- Update feature system for the crate [#138](https://github.com/dusk-network/poseidon252/issues/138)
- Change `PoseidonLeaf` getter methods to return refs [#143](https://github.com/dusk-network/poseidon252/issues/143)

### Removed
- Remove `anyhow` and `thiserror` from deps [#132](https://github.com/dusk-network/poseidon252/issues/132)
- Remove `PoseidonWalkableIterator` and `PoseidonWalkableAnnotation` [#125](https://github.com/dusk-network/poseidon252/issues/125)
- Remove `canon_host` feature checks from CI [#136](https://github.com/dusk-network/poseidon252/issues/136)
- Remove `anyhow` and `thiserror` usage [#132](https://github.com/dusk-network/poseidon252/issues/132)
- Remove `microkelvin` requirements from Tree [#146](https://github.com/dusk-network/Poseidon252/issues/146)

### Fixed

- Fix Readme.md import from lib.rs [#148](https://github.com/dusk-network/poseidon252/issues/148)

## [0.20.0] - 2021-04-06

### Changed

- Update `dusk-plonk` from `0.6` to `0.7` #119
- Update `dusk-hades` from `0.14` to `0.15` #119

### Fixed

- Merkle Opening constant circuit description [#122]

## [0.19.0] - 2021-03-11

### Changed

- Update `dusk-plonk` from `0.5` to `0.6` #117
- Update `dusk-hades` from `0.13` to `0.14`

## [0.18.0] - 2021-02-11

### Changed

- Change crate's name from `Poseidon252` to `dusk-poseidon`
- Implement `Canon` for `PoseidonBranch`

## [0.17.0] - 2021-02-01

### Changed

- Sponge gadget import path simplified.

### Fixed

- PoseidonBranch minimum depth fixed. [#112](https://github.com/dusk-network/poseidon252/issues/112)

## [0.16.0] - 2021-01-27

### Changed

- Update canonical to v0.5
- Update dusk-bls12_381 to v0.6
- Update dusk-jubjub to v0.8
- Update dusk-plonk to v0.5
- Update hades252 to v0.12.0
- Remove `hex` crate for unit test in favor of `dusk-bytes`
- Update CHANGELOG to ISO 8601
- to/from bytes methods of `PoseidonCipher` refactored in favor of dusk-bytes

## [0.15.0] - 2020-12-04

### Fixed

- PoseidonMaxAnnotation borrow fix for latest microkelvin.

## [0.14.1] - 2020-11-21

### Changed

- Sponge hash defined as a no-std function.

## [0.14.0] - 2020-11-17

### Changed

- No-Std compatibility.

## [0.13.1] - 2020-11-06

### Changed

- Feature split between `canon` and `canon_host` for constrained and unconstrained environments.
- Canon implementation for PoseidonTree.

## [0.13.0] - 2020-11-04

### Changed

- PoseidonLeaf pos setter for API consistency with Phoenix

### Removed

- PoseidonCipher std::io implementations

## [0.12.0] - 2020-11-04

### Added

- Gate-featured `canonical` impl.
- `PoseidonAnnotation` as generic to support walkable implementations

## [0.11.0] - 2020-10-30

### Changed

- Bump `hades252` to `v0.10.0`
- Major refactor on the poseidon tree to comply with the simplifications provided by microkelvin

## [0.10.0] - 2020-10-05

### Changed

- Bump `hades252` to `v0.9.0`
- Bump `dusk-plonk` to `v0.3.1`

## [0.9.0] - 2020-10-04

### Added

- `root()` fn for `PoseidonBranch`.

### Changed

- Padding implementation for `PoseidonBranch` with opening gadgets.

### Removed

- Extension fn's from the crate.

## [0.8.1] - 2020-10-01

### Changed

- Implement `inner` and `inner_mut` methods on PoseidonTree

## [0.8.0] - 2020-09-29

### Changed

- Use `dusk-plonk` `v0.2.11`
- Use `hades252 0.8.0`

## [0.7.0] - 2020-09-23

### Changed

- Removed PI constraint from `merkle_opening_gadget` to implement
  `CircuitBuilder` trait.
- Use `nstack 0.5.0`

## [0.6.4] - 2020-09-07

### Added

- `PoseidonCipher` from/to bytes.

## [0.6.3] - 2020-09-01

### Added

- Fixed_len hashing tools with variable input and output scalars.

## [0.6.2] - 2020-08-27

### Added

- `PoseidonCipher` zk encrypt and decrypt functions.

## [0.6.1] - 2020-08-13

### Changed

- `add_constant_witness` method replacement by `add_witness_to_circuit_description`.
- Changed `dusk-plonk` version to `v0.2.7`.
- Changed `Hades252` version to `v0.7.0`.

## [0.6.0] - 2020-08-07

### Changed

- Use `dusk-plonk v0.2.0` as dependency.
- Refactor the tests related to Proof generation to work with the Prover&Verifier abstraction.

### Fixed

- Constrain `eom` in sponge_hash function.

### Added

- Poseidon cipher encryption, decryption and plonk gadget for zk prove of encryption with a key.

## [0.5.0] - 2020-07-07

### Added

- `PoseidonTree` abstraction with padding and Proof gen. capabilities.

## [0.4.0] - 2020-06-30

### Changed

- Use NarrowHAMT for ctsize Proofs & padded Branches instead of NStack.

### Removed

- NStack dependencies are no longer needed nor used.

## [0.3.0] - 2020-06-23

### Added

- Merkle-Tree Opening inclusion proof generation capabilities.

- Methods for generating ZKProofs with PLONK
  getting a kelvin::Branch.

- Use Nstack for merkle-tree branch type.

## [0.2.0] - 2020-06-15

### Added

- PLONK as ZKP algorithm for the poseidon-hash
  functions.

- Optimization on the Sponge hash fn to skip useless addition if the width of the messages is the appropiate one to do it. (WIDTH < HADES_WIDTH -1).

### Changed

- Both the merkle-hash and the sponge-hash techniqes use now PLONK instead of Bulletproofs.

### Removed

- Bulletproofs and Curve25519 as dependencies since we no longer use them.

## [0.1.0] - 2020-02-10

### Added

- Poseidon252 Sponge-hash impl with BulletProofs.
- Variants of sponge for `Scalar` & `Gadget(Variable/LC)`.
