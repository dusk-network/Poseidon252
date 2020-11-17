// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

mod annotation;
mod branch;
mod leaf;
mod tree;

pub(crate) mod hash;

#[cfg(feature = "std")]
mod zk;

#[cfg(test)]
mod tests;

pub use annotation::{
    PoseidonAnnotation, PoseidonMaxAnnotation, PoseidonTreeAnnotation,
    PoseidonWalkableAnnotation,
};
pub use branch::{PoseidonBranch, PoseidonLevel};
pub use leaf::PoseidonLeaf;
pub use tree::{PoseidonTree, PoseidonTreeIterator};

#[cfg(feature = "std")]
pub use zk::merkle_opening;
