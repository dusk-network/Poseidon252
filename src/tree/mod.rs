// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! # Dusk-Poseidon Merkle Tree
//!
//! Implementation of a Merkle Tree with a Dusk-Poseidon backend and zero-knowledge opening proof powered by PLONK.
//!
//! ### Example
//!
//! ```rust
//! #[cfg(feature = "std")]
//! {
//! use anyhow::Result;
//! use canonical_derive::Canon;
//! use dusk_plonk::prelude::*;
//! use dusk_poseidon::tree::{merkle_opening, PoseidonAnnotation, PoseidonLeaf, PoseidonTree};
//! use rand_core::OsRng;
//!
//! // Constant depth of the merkle tree
//! const DEPTH: usize = 17;
//!
//! // Leaf representation
//! #[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon)]
//! struct DataLeaf {
//!     data: BlsScalar,
//!     pos: u64,
//! }
//!
//! // Example helper
//! impl From<u64> for DataLeaf {
//!     fn from(n: u64) -> DataLeaf {
//!         DataLeaf {
//!             data: BlsScalar::from(n),
//!             pos: n,
//!         }
//!     }
//! }
//!
//! // Any leaf of the poseidon tree must implement `PoseidonLeaf`
//! impl PoseidonLeaf for DataLeaf {
//!     // Cryptographic hash of the data leaf
//!     fn poseidon_hash(&self) -> BlsScalar {
//!         self.data
//!     }
//!
//!     // Position on the tree
//!     fn pos(&self) -> u64 {
//!         self.pos
//!     }
//!
//!     // Method used to set the position on the tree after the `PoseidonTree::push` call
//!     fn set_pos(&mut self, pos: u64) {
//!         self.pos = pos;
//!     }
//! }
//!
//! fn main() -> Result<()> {
//!     // Create the ZK keys
//!     let pub_params = PublicParameters::setup(1 << 15, &mut OsRng)?;
//!     let (ck, ok) = pub_params.trim(1 << 15)?;
//!
//!     // Instantiate a new tree.
//!     let mut tree: PoseidonTree<DataLeaf, PoseidonAnnotation, DEPTH> = PoseidonTree::new();
//!
//!     // Append 1024 elements to the tree
//!     for i in 0..1024 {
//!         let l = DataLeaf::from(i as u64);
//!         tree.push(l).unwrap();
//!     }
//!
//!     // Create a merkle opening tester gadget
//!     let gadget_tester = |composer: &mut StandardComposer,
//!                          tree: &PoseidonTree<DataLeaf, PoseidonAnnotation, DEPTH>,
//!                          n: usize| {
//!         let branch = tree.branch(n as u64).unwrap().unwrap();
//!         let root = tree.root().unwrap();
//!
//!         let root_p = merkle_opening::<DEPTH>(composer, &branch);
//!         composer.constrain_to_constant(root_p, BlsScalar::zero(), Some(-root));
//!     };
//!
//!     // Define the transcript initializer for the ZK backend
//!     let label = b"opening_gadget";
//!     let pos = 0;
//!
//!     // Create a merkle opening ZK proof
//!     let mut prover = Prover::new(label);
//!     gadget_tester(prover.mut_cs(), &tree, pos);
//!     prover.preprocess(&ck)?;
//!     let proof = prover.prove(&ck)?;
//!
//!     // Verify the merkle opening proof
//!     let mut verifier = Verifier::new(label);
//!     gadget_tester(verifier.mut_cs(), &tree, pos);
//!     verifier.preprocess(&ck)?;
//!     let pi = verifier.mut_cs().construct_dense_pi_vec();
//!     verifier.verify(&proof, &ok, &pi).unwrap();
//!
//!     Ok(())
//! }
//! }
//! ```

mod annotation;
mod branch;
mod leaf;
mod tree;

#[cfg(feature = "std")]
mod zk;

#[cfg(test)]
mod tests;

pub use annotation::{
    PoseidonAnnotation, PoseidonMaxAnnotation, PoseidonTreeAnnotation,
};
pub use branch::{PoseidonBranch, PoseidonLevel};
pub use leaf::PoseidonLeaf;
pub use tree::PoseidonTree;

#[cfg(feature = "std")]
pub use zk::merkle_opening;
