# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.35.0] - 2024-02-28

### Changed

- Rename trait `hades::Strategy` to `hades::Permutation` [#243]
- Rename struct `hades::ScalarStrategy` to `hades::ScalarPermutation` [#243]
- Rename struct `hades::GadgetStrategy` to `hades::GadgetPermutaiton` [#243]
- Reduce the number of `ROUND_CONSTANTS` from 960 to 335 [#246]
- Remove the constants iterator in favor of indexing the constants array directly [#246]
- Change `ROUND_CONSTANTS` into a two-dimensional array [#246]
- Rename `TOTAL_FULL_ROUNDS` to `FULL_ROUNDS` [#246]

### Removed

- Remove `hades::Strategy`, `hades::ScalarStrategy` and `hades::GadgetStrategy` from public API [#243]
- Remove `dusk-hades` dependency [#240]

### Added

- Add the code for the hades permutation to crate [#240]
- Add internal `permute` and `permute_gadget` functions to `hades` module [#243]

## [0.34.0] - 2024-01-24

### Changed

- Restructure crate features [#184]

### Removed

- Remove `default` and `alloc` features [#184]

### Added

- Add `zk` and `cipher` features [#184]

## [0.33.0] - 2024-01-03

### Changed

- Update `dusk-plonk` to 0.19
- Update `dusk-hades` to 0.24

## [0.32.0] - 2023-12-13

### Changed

- Update `dusk-bls12_381` to 0.13
- Update `dusk-jubjub` to 0.14
- Update `dusk-plonk` to 0.18
- Update `dusk-hades` to 0.23

## [0.31.0] - 2023-10-11

### Changed

- Update `dusk-bls12_381` to 0.12
- Update `dusk-jubjub` to 0.13
- Update `dusk-plonk` to 0.16
- Update `dusk-hades` to 0.22

## [0.30.1] - 2023-06-28

### Fixed

- Fix missing `rkyv` feature

## [0.30.0] - 2023-06-28

### Changed

- Update `dusk-plonk` from `0.13` to `0.14`
- Update `dusk-hades` from `0.20` to `0.21`

### Added

- Add sponge over fixed input length for merkle tree hashing [#215]

## [0.29.0] - 2023-05-17

### Removed

- Remove merkle tree logic from this crate [#212]

## [0.28.2] - 2023-04-06

### Added

- Add benchmark for running sponge gadged on 5 BlsScalar (one permutation) [#206]
- Add benchmarks for cypher in native and zk [#197]

## [0.28.1] - 2023-01-18

### Added

- Implement `dusk_bytes::Serializable` for `PoseidonBranch` and `PoseidonLevel` [#203]
- Add benchmarks for merkle opening proof [#197]

### Changed

- Derive `Copy` for `PoseidonBranch` [#200]

## [0.28.0] - 2022-11-10

### Changed

- Update `dusk-plonk` from `0.12` to `0.13`
- Update `dusk-hades` from `0.19` to `0.20`

## [0.27.0] - 2022-10-19

### Added

- Add support for `rkyv-impl` under `no_std`
- Add `ranno` version `0.1` to dependencies [#180]

### Changed

- Change `PoseidonBranch` to have two fields - `root` and `path`. The path is
  now a fixed length array. [#189]
- Change `PoseidonTree` to build only with the `alloc` feature [#180]
- Change `PoseidonTree` to take a generic `Keyed` over the leaf type
  instead of a `PoseidonAnnotation` [#180]
- Make `PoseidonTree::new` const [#180]
- Update `microkelvin` from `0.15` to `0.17` [#180]
- Update `nstack` from `0.14.0-rc` to `0.16` [#180]

### Removed

- Remove `PoseidonBranch` `Default` implementation [#189]
- Remove `std` feature [#180]
- Remove `canon` and `persistence` features [#180]
- Remove `Error` struct [#180]
- Remove `canonical` and `canonical-derive` from dependencies [#180]
- Remove `PoseidonMaxAnnotation` [#180]

### Fixed

- Fix merkle opening circuit [#181]
- Fix CHANGELOG version links [#191]

## [0.26.0] - 2022-08-17

### Added

- Add `rkyv` implementation behind feature gate [#175]

### Changed

- Update `dusk-bls12_381` from `0.8` to `0.11`
- Update `dusk-jubjub` from `0.10` to `0.12`
- Update `dusk-hades` from `0.17.0-rc` to `0.19`
- Update `canonical` from `0.6` to `0.7`
- Update `canonical_derive` from `0.6` to `0.7`
- Update `microkelvin` from `0.14` to `0.15`
- Update `nstack` from `0.13` to `0.14.0-rc`
- Update `dusk-plonk` from `0.9` to `0.12`
- Change merkle opening to constrain leaf [#162]
- Export `sponge::truncated::hash` regardless of `alloc` feature [#167]
- Remove useless `let` in `sponge::truncated`

### Fixed

- Fix module injection for `tree` and `cipher` modules

## [0.22.0] - 2021-07-27

### Changed

- Update `microkelvin` from `0.6` to `0.10` [#158]
- Update `nstack` from `0.9` to `0.10` [#158]

## [0.21.0] - 2021-07-05

### Added

- Add integration tests with examples of custom walker iterators [#134]
- Add `persistance` feature to the crate [#151]
- Add `truncated` module in sponge to deal with scalar conversions [#153]

### Changed

- Change the tree logic to be compatible with `microkelvin v0.9` [#151]
- Changed toolchain-file version to nightly-2021-06-06 [#149]
- Change feature set config for the crate [#138]
- Update `error` module to be no_std compatible [#132]
- Update to latest `dusk-poseidon`, `dusk-bls12_381` and `dusk-jubjub` [#126]
- Update to latest `microkelvin v0.9`, `nstack v0.9` and `canonical v0.6` [#125]
- Update randomness provider to `rand_core` [#127]
- Change trait bound system for `PoseidonTree` [#125]
- Update `PoseidonTreeAnnotation` to be an autotrait [#125]
- Update feature system for the crate [#138]
- Change `PoseidonLeaf` getter methods to return refs [#143]

### Removed

- Remove `anyhow` and `thiserror` from deps [#132]
- Remove `PoseidonWalkableIterator` and `PoseidonWalkableAnnotation` [#125]
- Remove `canon_host` feature checks from CI [#136]
- Remove `anyhow` and `thiserror` usage [#132]
- Remove `microkelvin` requirements from Tree [#146]

### Fixed

- Fix Readme.md import from lib.rs [#148]

## [0.20.0] - 2021-04-06

### Changed

- Update `dusk-plonk` from `0.6` to `0.7` [#119]
- Update `dusk-hades` from `0.14` to `0.15` [#119]

### Fixed

- Merkle Opening constant circuit description [#122]

## [0.19.0] - 2021-03-11

### Changed

- Update `dusk-plonk` from `0.5` to `0.6` [#117]
- Update `dusk-hades` from `0.13` to `0.14`

## [0.18.0] - 2021-02-11

### Changed

- Change crate's name from `Poseidon252` to `dusk-poseidon`
- Implement `Canon` for `PoseidonBranch`

## [0.17.0] - 2021-02-01

### Changed

- Sponge gadget import path simplified.

### Fixed

- PoseidonBranch minimum depth fixed. [#112]

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

## [0.13.2] - 2020-11-11

### Changed

- Update Hades version and libraries dependent on BLS and JubJub

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

- Optimization on the Sponge hash fn to skip useless addition if the width of the messages is the appropiate one to do it. (`WIDTH < HADES_WIDTH -1`).

### Changed

- Both the merkle-hash and the sponge-hash techniques use now PLONK instead of Bulletproofs.

### Removed

- Bulletproofs and Curve25519 as dependencies since we no longer use them.

## [0.1.0] - 2020-02-10

### Added

- Poseidon252 Sponge-hash impl with BulletProofs.
- Variants of sponge for `Scalar` & `Gadget(Variable/LC)`.

<!-- ISSUES -->
[#246]: https://github.com/dusk-network/poseidon252/issues/246
[#243]: https://github.com/dusk-network/poseidon252/issues/243
[#240]: https://github.com/dusk-network/poseidon252/issues/240
[#215]: https://github.com/dusk-network/poseidon252/issues/215
[#212]: https://github.com/dusk-network/poseidon252/issues/212
[#206]: https://github.com/dusk-network/poseidon252/issues/206
[#203]: https://github.com/dusk-network/poseidon252/issues/203
[#200]: https://github.com/dusk-network/poseidon252/issues/200
[#198]: https://github.com/dusk-network/poseidon252/issues/198
[#197]: https://github.com/dusk-network/Poseidon252/issues/197
[#189]: https://github.com/dusk-network/poseidon252/issues/189
[#184]: https://github.com/dusk-network/poseidon252/issues/184
[#181]: https://github.com/dusk-network/poseidon252/issues/181
[#180]: https://github.com/dusk-network/poseidon252/issues/180
[#175]: https://github.com/dusk-network/poseidon252/issues/175
[#167]: https://github.com/dusk-network/poseidon252/issues/167
[#162]: https://github.com/dusk-network/poseidon252/issues/162
[#158]: https://github.com/dusk-network/poseidon252/issues/158
[#153]: https://github.com/dusk-network/poseidon252/issues/153
[#151]: https://github.com/dusk-network/poseidon252/issues/151
[#149]: https://github.com/dusk-network/poseidon252/issues/149
[#148]: https://github.com/dusk-network/poseidon252/issues/148
[#146]: https://github.com/dusk-network/poseidon252/issues/146
[#143]: https://github.com/dusk-network/poseidon252/issues/143
[#138]: https://github.com/dusk-network/poseidon252/issues/138
[#136]: https://github.com/dusk-network/poseidon252/issues/136
[#134]: https://github.com/dusk-network/poseidon252/issues/134
[#132]: https://github.com/dusk-network/poseidon252/issues/132
[#127]: https://github.com/dusk-network/poseidon252/issues/127
[#126]: https://github.com/dusk-network/poseidon252/issues/126
[#125]: https://github.com/dusk-network/poseidon252/issues/125
[#122]: https://github.com/dusk-network/poseidon252/issues/122
[#119]: https://github.com/dusk-network/poseidon252/issues/119
[#117]: https://github.com/dusk-network/poseidon252/issues/117
[#112]: https://github.com/dusk-network/poseidon252/issues/112

<!-- VERSIONS -->
[Unreleased]: https://github.com/dusk-network/poseidon252/compare/v0.35.0...HEAD
[0.35.0]: https://github.com/dusk-network/poseidon252/compare/v0.34.0...v0.35.0
[0.34.0]: https://github.com/dusk-network/poseidon252/compare/v0.33.0...v0.34.0
[0.33.0]: https://github.com/dusk-network/poseidon252/compare/v0.32.0...v0.33.0
[0.32.0]: https://github.com/dusk-network/poseidon252/compare/v0.31.0...v0.32.0
[0.31.0]: https://github.com/dusk-network/poseidon252/compare/v0.30.1...v0.31.0
[0.30.1]: https://github.com/dusk-network/poseidon252/compare/v0.30.0...v0.30.1
[0.30.0]: https://github.com/dusk-network/poseidon252/compare/v0.29.2...v0.30.0
[0.29.0]: https://github.com/dusk-network/poseidon252/compare/v0.28.2...v0.29.0
[0.28.2]: https://github.com/dusk-network/poseidon252/compare/v0.28.1...v0.28.2
[0.28.1]: https://github.com/dusk-network/poseidon252/compare/v0.28.0...v0.28.1
[0.28.0]: https://github.com/dusk-network/poseidon252/compare/v0.27.0...v0.28.0
[0.27.0]: https://github.com/dusk-network/poseidon252/compare/v0.26.0...v0.27.0
[0.26.0]: https://github.com/dusk-network/poseidon252/compare/v0.22.0...v0.26.0
[0.22.0]: https://github.com/dusk-network/poseidon252/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/dusk-network/poseidon252/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/dusk-network/poseidon252/compare/v0.19.0...v0.20.0
[0.19.0]: https://github.com/dusk-network/poseidon252/compare/v0.18.0...v0.19.0
[0.18.0]: https://github.com/dusk-network/poseidon252/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/dusk-network/poseidon252/compare/v0.16.0...v0.17.0
[0.16.0]: https://github.com/dusk-network/poseidon252/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/dusk-network/poseidon252/compare/v0.14.1...v0.15.0
[0.14.1]: https://github.com/dusk-network/poseidon252/compare/v0.14.0...v0.14.1
[0.14.0]: https://github.com/dusk-network/poseidon252/compare/v0.13.2...v0.14.0
[0.13.2]: https://github.com/dusk-network/poseidon252/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/dusk-network/poseidon252/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/dusk-network/poseidon252/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/dusk-network/poseidon252/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/dusk-network/poseidon252/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/dusk-network/poseidon252/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/dusk-network/poseidon252/compare/v0.8.1...v0.9.0
[0.8.1]: https://github.com/dusk-network/poseidon252/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/dusk-network/poseidon252/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/dusk-network/poseidon252/compare/v0.6.4...v0.7.0
[0.6.4]: https://github.com/dusk-network/poseidon252/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/dusk-network/poseidon252/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/dusk-network/poseidon252/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/dusk-network/poseidon252/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/dusk-network/poseidon252/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/dusk-network/poseidon252/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dusk-network/poseidon252/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dusk-network/poseidon252/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dusk-network/poseidon252/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dusk-network/poseidon252/releases/tag/v0.1.0
