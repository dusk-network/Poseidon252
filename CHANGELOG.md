# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Optimization on the Sponge hash fn to skip useless addition if the width of the messages is the appropiate one to do it. (WIDTH < HADES_WIDTH -1).
- dusk-bls12_381 & dusk-plonk as dependencies.

### Changed
- Sponge hash refactor with gadget and scalar versions using plonk as Proof System.

### Removed
- Legacy tests that no longer apply.
- Bulletproofs & Curve25519-dalek as dependencies

## [0.1.0] - 10-02-20

### Added

- Poseidon252 Sponge-hash impl with BulletProofs.
- Variants of sponge for `Scalar` & `Gadget(Variable/LC)`.

### Changed

### Fixed

### Removed
