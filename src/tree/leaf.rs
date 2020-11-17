use canonical::{Canon, Store};
use dusk_bls12_381::BlsScalar;

/// A struct that will be used as a poseidon tree leaf must implement this trait
///
/// After [`PoseidonTree::push`], `tree_pos_mut` will be called to set the
/// index of the leaf on the tree
pub trait PoseidonLeaf<S>: Canon<S> + Clone
where
    S: Store,
{
    /// Poseidon hash implementation of the leaf structure.
    ///
    /// The result of this function will be used as opening for the merkle tree.
    fn poseidon_hash(&self) -> BlsScalar;

    /// Index of the leaf structure on the merkle tree.
    fn pos(&self) -> u64;

    /// Index of the leaf structure on the merkle tree.
    ///
    /// This method is internally used to set the index after the data has been inserted in the
    /// merkle tree.
    fn set_pos(&mut self, pos: u64);
}
