//! Definitions of the merkle tree structure seen in Poseidon.

use crate::merkle_lvl_hash::hash;
use dusk_bls12_381::Scalar;
use hades252::ScalarStrategy;
use hades252::WIDTH;
use kelvin::{Branch, ByteHash, Compound, Handle};
use std::borrow::Borrow;

/// Maximum arity supported for trees.
///
/// This is due to the fact that actually we rely in Hades252 crate
/// which `WIDTH` parameter is 5.
pub const ARITY: usize = WIDTH - 1;

/// The `Poseidon` structure will accept a number of inputs equal to the arity.
///
/// The levels are ordered so the first element of `levels` is actually the bottom
/// level of the Kelvin tree.
#[derive(Debug, Clone, PartialEq)]
pub struct PoseidonBranch {
    pub(crate) root: Scalar,
    pub(crate) levels: Vec<PoseidonLevel>,
}

/// We will need to define the logic on the HashingAnnotation so we
/// directly get the `Level` with the `bitflags` item.
///
/// So we can directly assume that
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
        for level in branch.levels().iter().skip(1).rev() {
            poseidon_branch.levels.push({
                let mut pos_level = PoseidonLevel::default();
                level
                    .children()
                    .iter()
                    .zip(pos_level.leaves.iter_mut())
                    // Copy in poseidon_branch the leave values of the actual level.
                    // If they're null, place a Scalar::zero() inside of them.
                    .for_each(|(src, dest)| {
                        *dest = match src.annotation() {
                            Some(borrow) => {
                                let annotation: &Scalar = (*borrow).borrow();
                                *annotation
                            }
                            None => Scalar::zero(),
                        };
                    });
                // Once we have the level, compute the upper hash and look for it in the
                // upper level
                // XXX: We will probably need a peekable iter to get the upper level leaf and
                // commpare it.
                level.offset();
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
    pub(crate) upper_lvl_hash: Scalar,
    pub(crate) leaves: [Scalar; WIDTH],
}

impl Default for PoseidonLevel {
    fn default() -> Self {
        PoseidonLevel {
            upper_lvl_hash: Scalar::zero(),
            leaves: [Scalar::zero(); WIDTH],
        }
    }
}

/*
impl<'a> From<&'a [Scalar; ARITY]> for PoseidonLevel {
    /// Actually just supporting levels with an Arity of 4.
    fn from(level: &'a [Scalar; ARITY]) -> Self {
        let mut accum = 0u64;
        let mut res = [Scalar::zero(); WIDTH];
        level
            .iter()
            .zip(res.iter_mut().skip(1))
            .enumerate()
            .for_each(|(idx, (l, r))| {
                *r = *l;
                accum += 1u64 << idx;
            });
        // Set bitflags as first element.
        res[0] = Scalar::from(accum);
        PoseidonLevel { leaves: res }
    }
}*/

#[cfg(test)]
mod tests {
    use super::*;
    use kelvin::{Blake2b, Combine, Content, ErasedAnnotation, Sink, Source};
    use kelvin_hamt::{HAMTSearch, HAMT};
    use std::io;
    use std::io::Read;

    #[derive(Clone, Debug)]
    struct PoseidonAnnotation(Scalar);

    impl<A> Combine<A> for PoseidonAnnotation {
        /// This implements the logic that Kelvin needs in otder to know how to
        /// hash an entire merkle tree level.
        ///
        /// It includes the padding logic and the generation of the bitflags.
        fn combine<E>(elements: &[E]) -> Option<Self>
        where
            A: Borrow<Self> + Clone,
            E: ErasedAnnotation<A>,
        {
            let mut leaves: Vec<Scalar> = Vec::new();
            elements.iter().enumerate().for_each(|(idx, element)| {
                match element.annotation() {
                    Some(annotation) => {
                        let h: &PoseidonAnnotation = (*annotation).borrow();
                        leaves[idx] = h.0;
                    }
                    None => leaves[idx] = Scalar::zero(),
                };
            });
            let res = hash::merkle_level_hash(&leaves);
            Some(PoseidonAnnotation(res))
        }
    }

    impl<H> Content<H> for PoseidonAnnotation
    where
        H: ByteHash,
    {
        fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
            self.0.to_bytes().persist(sink)
        }
        fn restore(source: &mut Source<H>) -> io::Result<Self> {
            let mut bytes = [0u8; 32];
            for (idx, byte) in source.bytes().enumerate() {
                bytes[idx] = byte.unwrap();
            }
            Ok(PoseidonAnnotation(Scalar::from_bytes(&bytes).unwrap()))
        }
    }

    impl<T> From<&T> for PoseidonAnnotation
    where
        T: ByteHash,
    {
        fn from(t: &T) -> Self {
            unimplemented!()
        }
    }

    #[test]
    fn merkle_proof() {
        let mut hamt = HAMT::new();

        for i in 0..1024 {
            hamt.insert(i, PoseidonAnnotation(Scalar::from(i as u64)))
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
        }
    }
}
