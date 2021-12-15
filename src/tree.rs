// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Implementation of a Merkle Tree with a Dusk-Poseidon backend and zero-knowledge opening proof powered by PLONK.

mod annotation;
mod branch;
mod leaf;
mod tree;
mod zk;

pub use annotation::{
    PoseidonAnnotation, PoseidonMaxAnnotation, PoseidonTreeAnnotation,
};
pub use branch::{PoseidonBranch, PoseidonLevel};
pub use leaf::PoseidonLeaf;
pub use tree::PoseidonTree;
pub use zk::merkle_opening;
