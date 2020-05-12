//! Definitions of the merkle tree structure seen in Poseidon.

use crate::ARITY;
use dusk_bls12_381::Scalar;
use hades252::WIDTH;
use kelvin::{Branch, ByteHash, Compound};
use std::borrow::Borrow;

/// The `Poseidon` structure will accept a number of inputs equal to the arity.
///
/// The levels are ordered so the first element of `levels` is actually the bottom
/// level of the Kelvin tree.
#[derive(Debug, Clone, PartialEq)]
pub struct PoseidonBranch {
    pub(crate) root: Scalar,
    pub(crate) levels: Vec<PoseidonLevel>,
}

/// Provides a conversion between Branch and PoseidonBranch.
///
/// We extract the data from the `Branch` and store it appropiately
/// inside of the `PoseidonBranch` structure with the bitflags already
/// computed and the offsets pointing to the next levels pointing also to
/// the correct places.
impl<C, H> From<Branch<'_, C, H>> for PoseidonBranch
where
    C: Compound<H>,
    C::Annotation: Borrow<Scalar>,
    H: ByteHash,
{
    fn from(branch: Branch<C, H>) -> PoseidonBranch {
        let mut poseidon_branch = PoseidonBranch::with_capacity(branch.levels().len() - 1);
        // Skip root and store it directly.
        poseidon_branch.root = branch
            .levels()
            .first()
            .unwrap()
            .annotation()
            .unwrap()
            .borrow()
            .to_owned();
        // Store the levels with the bitflags already computed inside
        // of our PoseidonBranch structure.
        // We skip the root level and we reverse the levels iterator to start
        // storing the levels from the bottom of the branch.
        for level in branch.levels().iter().skip(1).rev() {
            // Generate a default mutable `PoseidonLevel`, add the corresponding data
            // extracted from the `Branch` and push it to our poseidon branch previously
            // generated.
            poseidon_branch.levels.push({
                let mut pos_level = PoseidonLevel::default();
                let mut level_bitflags = 0u64;
                level
                    .children()
                    .iter()
                    // Copy in poseidon_branch the leave values of the actual level with an
                    // offset of one. So then we can add the bitflags at the beggining as the
                    // first item of the `WIDTH` ones.
                    .zip(pos_level.leaves.iter_mut().skip(1))
                    // If they're null, place a Scalar::zero() inside of them as stated on the
                    // Poseidon Hash paper.
                    .enumerate()
                    .for_each(|(idx, (src, dest))| {
                        *dest = match src.annotation() {
                            Some(borrow) => {
                                let annotation: &Scalar = (*borrow).borrow();
                                // If the Annotation contains a value, we set the bitflag to 1.
                                // Since the first element will be the most significant bit of the
                                // bitflags, we need to shift it according to the `ARITY`.
                                //
                                // So for example:
                                // A level with: [Some(val), None, None, None] should correspond to
                                // Bitflags(1000). This means that we need to shift the first element
                                // by `ARITY` and lately decrease the shift order by `idx`.
                                level_bitflags += 1u64 << (ARITY - idx);
                                *annotation
                            }
                            None => Scalar::zero(),
                        };
                    });
                // Now we should have our bitflags value computed as well as the
                // `WIDTH` leaves set on the [1..4] positions of our poseidon_level.
                //
                // We need now to add the bitflags element in pos_level.leaves[0]
                pos_level.leaves[0] = Scalar::from(level_bitflags);
                // Once we have the level, we get the position where the hash of this level is
                // stored on the upper level.
                // NOTE that this position is in respect of a WIDTH = `ARITY` so we need to
                // keep in mind that we've added an extra term (bitflags) and so, the index that
                // the branch is returning is indeed pointing one position before on the next level
                // that we will compute later. We just add 1 to it to inline the value with the
                // new `WIDTH`
                pos_level.upper_lvl_hash = level.offset() + 1;
                pos_level
            })
        }
        poseidon_branch
    }
}

impl PoseidonBranch {
    pub fn with_capacity(n: usize) -> Self {
        PoseidonBranch {
            root: Scalar::zero(),
            levels: Vec::with_capacity(n),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PoseidonLevel {
    pub(crate) upper_lvl_hash: usize,
    pub(crate) leaves: [Scalar; WIDTH],
}

impl Default for PoseidonLevel {
    fn default() -> Self {
        PoseidonLevel {
            upper_lvl_hash: 0usize,
            leaves: [Scalar::zero(); WIDTH],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing_utils::scalar_storage::StorageScalar;
    use kelvin_hamt::{HAMTSearch, HAMT};

    #[test]
    fn merkle_proof() {
        // XXX: We need to wait for kelvin to provide us with custom-ARITY tree generation.
        // Otherways, the proofs will not work correctly.

        /*let mut hamt = HAMT::new();

        for i in 0..1024 {
            hamt.insert(i, StorageScalar(Scalar::from(i as u64)))
                .unwrap();
        }
        // make a proof that (42, 42) is in the hamt

        if let Some(branch) = hamt.search(&mut HAMTSearch::from(&42)).unwrap() {
            let levels = branch.levels();

            for (i, level) in levels.iter().enumerate() {
                println!("level {}", i);
                for child in level.children() {
                    println!("  {:?}", child.annotation())
                }
            }
        }*/
        assert!(true)
    }
}
