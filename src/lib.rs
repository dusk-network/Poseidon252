// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! ![Build Status](https://travis-ci.com/dusk-network/Poseidon252.svg?branch=master)](https://travis-ci.com/dusk-network/Poseidon252)
//! ![Repository](https://dusk-network.github.io/Poseidon252/repo-badge.svg)](https://github.com/dusk-network/Poseidon252)
//! ![Documentation](https://dusk-network.github.io/Poseidon252/badge.svg)](https://dusk-network.github.io/Poseidon252/index.html)
//!
//! # Poseidon252
//! Reference implementation for the Poseidon Hashing algorithm.
//!
//! #### Reference
//!
//! [Starkad and Poseidon: New Hash Functions for Zero Knowledge Proof Systems](https://eprint.iacr.org/2019/458.pdf)
//!
//! This repository has been created so there's a unique library that holds the tools & functions
//! required to perform Poseidon Hashes.
//!
//! This hashes heavily rely on the Hades permutation, which is one of the key parts that Poseidon needs in order
//! to work.
//! This library uses the reference implementation of [Hades252](https://github.com/dusk-network/hades252) which has been
//! designed & build by the [Dusk-Network team](https://dusk.network/).
//!
//! **The library provides the two hashing techniques of Poseidon:**
//!
//! ## Sponge Hash
//! The `Sponge` techniqe in Poseidon allows to hash an unlimited ammount of data
//! into a single `Scalar`.
//! The sponge hash techniqe requires a padding to be applied before the data can
//! be hashed.
//!
//! This is done to avoid hash collitions as stated in the paper of the Poseidon Hash
//! algorithm. See: (https://eprint.iacr.org/2019/458.pdf)[https://eprint.iacr.org/2019/458.pdf].
//! The inputs of the `sponge_hash` are always `Scalar` or need to be capable of being represented
//! as it.
//!
//! The module provides two sponge hash implementations:
//! - Sponge hash using `Scalar` as backend. Which hashes the inputed `Scalar`s and returns a single
//! `Scalar`.
//!
//! - Sponge hash gadget using `dusk_plonk::Variable` as a backend. This techniqe is used/required
//! when you want to proof pre-images of unconstrained data inside of Zero-Knowledge PLONK circuits.
//!
//!
//! ## Merkle Hash
//! The Merkle Level Hashing is a technique that Poseidon is optimized-by-design
//! to perform.
//! This technique allows us to perform hashes of an entire Merkle Tree using
//! `Hades252` as backend.
//!
//! The technique requires the computation of a `bitflags` element which is always
//! positioned as the first item of the level when we hash it, and it basically generated
//! in respect of the presence or absence of a leaf in the tree level.
//! This allows to prevent hashing collitions.
//!
//! At the moment, this library is designed and optimized to work only with trees of `ARITY`
//! up to 4. **That means that trees with a bigger ARITY SHOULD NEVER be used with this lib.**
//! The module contains the implementation of 4 variants of the same algorithm to support the
//! majority of the configurations that the user may need:
//!
//! - Scalar backend for hashing Merkle Tree levels outside of ZK-Circuits whith two variants:
//! One of them computes the bitflags item while the other assumes that it has already been
//! computed and placed in the first Level position.
//!
//! - `dusk_plonk::Variable` backend for hashing Merkle Tree levels inside of ZK-Circuits,
//!  specifically, PLONK circuits. This implementation comes also whith two variants;
//! One of them computes the bitflags item while the other assumes that it has already been
//! computed and placed in the first Level position.
//!
//!
//!
//! ### Zero Knowledge Merkle Opening Proof example:
//!
//! ```ignore
//! use anyhow::Result;
//! use canonical::Canon;
//! use canonical_derive::Canon;
//! use canonical_host::MemStore;
//! use dusk_plonk::prelude::*;
//! use poseidon252::tree::zk::merkle_opening;
//! use poseidon252::tree::{PoseidonAnnotation, PoseidonTree};
//!
//! const DEPTH: usize = 17;
//!
//! #[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon)]
//! struct MockLeaf(pub BlsScalar);
//!
//! impl From<u64> for MockLeaf {
//!     fn from(n: u64) -> MockLeaf {
//!         MockLeaf(BlsScalar::from(n))
//!     }
//! }
//!
//! impl Into<BlsScalar> for &MockLeaf {
//!     fn into(self) -> BlsScalar {
//!         self.0
//!     }
//! }
//!
//! fn main() -> Result<()> {
//!     let pub_params = PublicParameters::setup(1 << 15, &mut rand::thread_rng())?;
//!     let (ck, ok) = pub_params.trim(1 << 15)?;
//!
//!     let mut tree: PoseidonTree<MockLeaf, PoseidonAnnotation, MemStore, DEPTH> =
//!         PoseidonTree::new();
//!
//!     for i in 0..1024 {
//!         let l = MockLeaf::from(i as u64);
//!         tree.push(l)?;
//!     }
//!
//!     let gadget_tester =
//!         |composer: &mut StandardComposer,
//!          tree: &PoseidonTree<MockLeaf, PoseidonAnnotation, MemStore, DEPTH>,
//!          n: usize| {
//!             let branch = tree.branch(n).unwrap().unwrap();
//!             let root = tree.root().unwrap();
//!
//!             let leaf = BlsScalar::from(n as u64);
//!             let leaf = composer.add_input(leaf);
//!
//!             let root_p = merkle_opening::<DEPTH>(composer, &branch, leaf);
//!             composer.constrain_to_constant(root_p, BlsScalar::zero(), -root);
//!         };
//!
//!     let label = b"opening_gadget";
//!     let idx = 0;
//!
//!     let mut prover = Prover::new(label);
//!     gadget_tester(prover.mut_cs(), &tree, idx);
//!     prover.preprocess(&ck)?;
//!     let proof = prover.prove(&ck)?;
//!
//!     let mut verifier = Verifier::new(label);
//!     gadget_tester(verifier.mut_cs(), &tree, idx);
//!     verifier.preprocess(&ck)?;
//!     let pi = verifier.mut_cs().public_inputs.clone();
//!     verifier.verify(&proof, &ok, &pi).unwrap();
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Documentation
//! This crate contains info about all of the functions that the library provides as well as the
//! documentation regarding the data structures that it exports. To check it, please feel free to go to
//! the [documentation page](https://dusk-network.github.io/Poseidon252/poseidon252/index.html)
//!
//! ## Licensing
//!
//! This code is licensed under Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for further info.
//!
//! ## About
//!
//! Implementation designed by the [dusk](https://dusk.network) team.
//!
//! ## Contributing
//! - If you want to contribute to this repository/project please, check [CONTRIBUTING.md](https://github.com/dusk-network/Poseidon252/blob/master/CONTRIBUTING.md)
//! - If you want to report a bug or request a new feature addition, please open an issue on this repository.

#![deny(missing_docs)]
#![feature(min_const_generics)]

/// Encryption and decryption implementation over a Poseidon cipher
pub mod cipher;
/// Module containing a fixed-length Poseidon hash implementation
pub mod perm_uses;
/// Reference implementation for the Poseidon Sponge hash function
pub mod sponge;
/// The module handling posedion-trees
#[cfg(feature = "canon")]
pub mod tree;
