//! Reference implementation for the Poseidon Sponge function
#![deny(missing_docs)]

///
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

/// This struct is a Wrapper type over the bls12-381 `Scalar` which has implemented
/// inside the logic to allows `Kelvin` Merkle Trees understand how to store `Scalar`s
/// inside of them leaves.
///
/// This Struct is the one that we will use inside of our SmartContract storage logic to
/// encode/compress all of our Data Structures data into a single `Scalar`.
pub use hashing_utils::scalar_storage::StorageScalar;

/// This structures should only be used if you want to elaborate custom Merkle-Tree proofs.
///
/// If that's not the case, you should just call the `merkle_proof` with the required fields
/// and forget about this structures since they're properly handled internally.
pub use merkle_proof::{PoseidonBranch, PoseidonLevel};
