use std::io;

use dusk_bls12_381::Scalar;
use kelvin::{
    annotation,
    annotations::{Cardinality, Count},
    Branch, BranchMut, ByteHash, Compound, Content, Sink, Source,
};
use nstack::NStack;

use crate::merkle_lvl_hash::hash::*;
use crate::merkle_proof::poseidon_branch::extend_scalar;
use crate::ARITY;
use crate::{PoseidonBranch, PoseidonLevel, StorageScalar};

annotation! {
    /// The annotation for the PoseidonTree
    pub struct PoseidonAnnotation {
        scalar: StorageScalar,
        count: Cardinality<u64>,
    }
}

/// A zk-friendly datastructure to store elements
pub struct PoseidonTree<T, H>
where
    T: Content<H>,
    for<'a> &'a T: Into<StorageScalar>,
    H: ByteHash,
{
    branch_depth: u16,
    inner: NStack<T, PoseidonAnnotation, H>,
}

impl<T, H> Clone for PoseidonTree<T, H>
where
    T: Content<H>,
    for<'a> &'a T: Into<StorageScalar>,
    H: ByteHash,
{
    fn clone(&self) -> Self {
        PoseidonTree {
            branch_depth: self.branch_depth,
            inner: self.inner.clone(),
        }
    }
}

impl<T, H> Content<H> for PoseidonTree<T, H>
where
    T: Content<H>,
    for<'a> &'a T: Into<StorageScalar>,
    H: ByteHash,
{
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        self.branch_depth.persist(sink)?;
        self.inner.persist(sink)
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        Ok(PoseidonTree {
            branch_depth: u16::restore(source)?,
            inner: NStack::restore(source)?,
        })
    }
}

impl<T, H> PoseidonTree<T, H>
where
    T: Content<H>,
    for<'a> &'a T: Into<StorageScalar>,
    H: ByteHash,
{
    /// Constructs a new empty PoseidonTree
    pub fn new(depth: usize) -> Self {
        PoseidonTree {
            branch_depth: depth as u16,
            inner: Default::default(),
        }
    }

    /// Returns the scalar root-hash of the poseidon tree
    ///
    /// This includes padding the value to the correct branch length equivalent
    pub fn root(&self) -> io::Result<Scalar> {
        if let Some(ann) = self.inner.annotation() {
            let borrow: &StorageScalar = ann.borrow();
            let scalar: Scalar = borrow.clone().into();

            // FIXME, depth could be inferred from the cardinality
            if let Some(branch) = self.get(0)? {
                let depth = branch.levels().len();
                Ok(extend_scalar(scalar, self.branch_depth as usize - depth))
            } else {
                unreachable!("Annotation in empty tree")
            }
        } else {
            // empty case, use an empty level for hashing
            let leaves = [Scalar::zero(); ARITY + 1];
            let level = PoseidonLevel { leaves, offset: 0 };
            let root = merkle_level_hash_without_bitflags(&level);
            Ok(extend_scalar(root, self.branch_depth as usize))
        }
    }

    /// Returns a poseidon branch pointing at the specific index
    ///
    /// This includes padding the value to the correct branch length equivalent
    pub fn poseidon_branch(
        &self,
        idx: u64,
    ) -> io::Result<Option<PoseidonBranch>> {
        Ok(self.inner.get(idx)?.map(|ref branch| {
            let mut pbranch: PoseidonBranch = branch.into();
            pbranch.extend(self.branch_depth as usize);
            pbranch
        }))
    }

    /// Push a new item onto the tree
    pub fn push(&mut self, t: T) -> io::Result<u64> {
        let idx = self.inner.count();
        self.inner.push(t)?;
        Ok(idx)
    }

    /// Get a branch reference to the element at index `idx`, if any
    pub fn get(
        &self,
        idx: u64,
    ) -> io::Result<Option<Branch<NStack<T, PoseidonAnnotation, H>, H>>> {
        self.inner.get(idx)
    }

    /// Get a mutable branch reference to the element at index `idx`, if any
    pub fn get_mut(
        &mut self,
        idx: u64,
    ) -> io::Result<Option<BranchMut<NStack<T, PoseidonAnnotation, H>, H>>>
    {
        self.inner.get_mut(idx)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use kelvin::Blake2b;

    #[test]
    fn insert() {
        let mut tree = PoseidonTree::<_, Blake2b>::new(17);

        for i in 0..128u64 {
            let idx = tree.push(StorageScalar::from(i)).unwrap();
            assert_eq!(idx, i);
        }

        assert!(true)
    }
}
