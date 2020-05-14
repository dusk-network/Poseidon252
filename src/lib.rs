//! Reference implementation for the Poseidon Sponge function
#![deny(missing_docs)]

/// Helpers for kelvin hashing & storing trait implementations
pub mod hashing_utils;
/// Reference implementation for the Poseidon Merkle hash function
pub mod merkle_lvl_hash;
/// Reference implementation for the gadget that builds a merkle opening proof
pub mod merkle_proof;
/// Reference implementation for the Poseidon Sponge hash function
pub mod sponge;

/// Maximum arity supported for trees.
///
/// This is due to the fact that actually we rely in Hades252 crate
/// which `WIDTH` parameter is 5.
pub const ARITY: usize = hades252::WIDTH - 1;

/// Wrapping struct that defines used to implement over it
/// the hashing logic that Kelvin needs in order to provide
/// Merkle Paths as `Branch` using Poseidon as the main Hasing
/// algorithm.
///
pub use hashing_utils::poseidon_annotation::PoseidonAnnotation;
