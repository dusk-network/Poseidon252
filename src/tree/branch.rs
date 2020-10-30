use canonical::{Canon, Store};
use core::borrow::Borrow;
use core::ops::Deref;
use dusk_plonk::prelude::BlsScalar;
use hades252::{ScalarStrategy, Strategy};
use microkelvin::{Annotation, Branch};
use nstack::NStack;

/// Represents a level of a branch on a given depth
#[derive(Debug, Default, Clone, Copy)]
pub struct PoseidonLevel {
    level: [BlsScalar; hades252::WIDTH],
    offset: usize,
}

impl PoseidonLevel {
    /// Represents the offset of a node for a given path produced by a branch
    /// in a merkle opening
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl Deref for PoseidonLevel {
    type Target = BlsScalar;

    fn deref(&self) -> &Self::Target {
        &self.level[self.offset]
    }
}

impl AsRef<[BlsScalar]> for PoseidonLevel {
    fn as_ref(&self) -> &[BlsScalar] {
        &self.level
    }
}

/// Represents a full path for a merkle opening
#[derive(Debug, Clone, Copy)]
pub struct PoseidonBranch<const DEPTH: usize>([PoseidonLevel; DEPTH]);

impl<const DEPTH: usize> PoseidonBranch<DEPTH> {
    /// Represents the root for a given path of an opening over a subtree
    pub fn root(&self) -> BlsScalar {
        *self.0[DEPTH - 1]
    }
}

impl<const DEPTH: usize> Deref for PoseidonBranch<DEPTH> {
    type Target = BlsScalar;

    fn deref(&self) -> &Self::Target {
        self.0[0].deref()
    }
}

impl<const DEPTH: usize> Default for PoseidonBranch<DEPTH> {
    fn default() -> Self {
        PoseidonBranch([PoseidonLevel::default(); DEPTH])
    }
}

impl<const DEPTH: usize> AsRef<[PoseidonLevel]> for PoseidonBranch<DEPTH> {
    fn as_ref(&self) -> &[PoseidonLevel] {
        &self.0
    }
}

impl<L, A, S, const DEPTH: usize> From<&Branch<'_, NStack<L, A, S>, S, DEPTH>>
    for PoseidonBranch<DEPTH>
where
    L: Canon<S>,
    L: Clone,
    for<'a> &'a L: Into<BlsScalar>,
    A: Canon<S>,
    A: Annotation<NStack<L, A, S>, S>,
    A: Borrow<BlsScalar>,
    S: Store,
{
    fn from(b: &Branch<'_, NStack<L, A, S>, S, DEPTH>) -> Self {
        let mut branch = PoseidonBranch::default();
        let mut depth = 0;

        b.levels()
            .iter()
            .rev()
            .zip(branch.0.iter_mut())
            .for_each(|(l, b)| {
                depth += 1;
                b.offset = l.offset() + 1;

                let mut flag = 1;
                let mut mask = 0;

                match &**l {
                    NStack::Leaf(l) => l
                        .iter()
                        .zip(b.level.iter_mut().skip(1))
                        .for_each(|(leaf, l)| {
                            if let Some(leaf) = leaf {
                                mask |= flag;
                                *l = leaf.into();
                            }

                            flag <<= 1;
                        }),
                    NStack::Node(n) => n
                        .iter()
                        .zip(b.level.iter_mut().skip(1))
                        .for_each(|(node, l)| {
                            if let Some(node) = node {
                                mask |= flag;
                                *l = *node.annotation().borrow();
                            }

                            flag <<= 1;
                        }),
                }

                b.level[0] = BlsScalar::from(mask);
            });

        if depth >= DEPTH {
            return branch;
        }

        let flag = BlsScalar::from(0b1000);
        let level = branch.0[depth - 1].level;
        let mut perm = [BlsScalar::zero(); hades252::WIDTH];

        let mut h = ScalarStrategy::new();
        branch.0.iter_mut().skip(depth).fold(level, |l, b| {
            perm.copy_from_slice(&l);
            h.perm(&mut perm);

            b.offset = 1;
            b.level[0] = flag;
            b.level[1] = perm[1];

            b.level
        });

        branch
    }
}
