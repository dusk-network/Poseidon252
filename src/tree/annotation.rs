use canonical::{Canon, Store};
use canonical_derive::Canon;
use core::borrow::Borrow;
use dusk_plonk::prelude::BlsScalar;
use hades252::{ScalarStrategy, Strategy};
use microkelvin::{Annotation, Cardinality};
use nstack::NStack;

/// A microkelvin annotation with the minimum data for a functional poseidon tree
///
/// The recommended usage for extended annotations for poseidon trees is to have
/// this structure as attribute of the concrete annotation, and reflect the borrows
/// of the cardinality and scalar to the poseidon annotation implementation.
#[derive(Debug, Clone, Canon)]
pub struct PoseidonAnnotation {
    cardinality: Cardinality,
    poseidon_root: BlsScalar,
}

impl PoseidonAnnotation {
    /// Return the scalar representation of the root of the annotated subtree
    pub fn poseidon_root(&self) -> &BlsScalar {
        &self.poseidon_root
    }
}

impl Borrow<Cardinality> for PoseidonAnnotation {
    fn borrow(&self) -> &Cardinality {
        &self.cardinality
    }
}

impl Borrow<BlsScalar> for PoseidonAnnotation {
    fn borrow(&self) -> &BlsScalar {
        &self.poseidon_root
    }
}

impl<L, S> Annotation<NStack<L, PoseidonAnnotation, S>, S>
    for PoseidonAnnotation
where
    L: Canon<S>,
    L: Clone,
    for<'a> &'a L: Into<BlsScalar>,
    S: Store,
{
    fn identity() -> Self {
        let cardinality = <Cardinality as Annotation<
            NStack<L, PoseidonAnnotation, S>,
            S,
        >>::identity();
        let poseidon_root = BlsScalar::zero();

        Self {
            cardinality,
            poseidon_root,
        }
    }

    fn from_leaf(leaf: &L) -> Self {
        let cardinality = <Cardinality as Annotation<
            NStack<L, PoseidonAnnotation, S>,
            S,
        >>::from_leaf(leaf);
        let poseidon_root = leaf.into();

        Self {
            cardinality,
            poseidon_root,
        }
    }

    fn from_node(node: &NStack<L, PoseidonAnnotation, S>) -> Self {
        let cardinality = <Cardinality as Annotation<
            NStack<L, PoseidonAnnotation, S>,
            S,
        >>::from_node(node);

        let mut perm = [BlsScalar::zero(); hades252::WIDTH];
        let mut flag = 1;
        let mut mask = 0;

        match node {
            NStack::Leaf(l) => {
                l.iter().zip(perm.iter_mut().skip(1)).for_each(|(l, p)| {
                    if let Some(l) = l {
                        mask |= flag;
                        *p = l.into();
                    }

                    flag <<= 1;
                });
            }

            NStack::Node(n) => {
                n.iter().zip(perm.iter_mut().skip(1)).for_each(|(n, p)| {
                    if let Some(n) = n {
                        mask |= flag;
                        *p = n.annotation().poseidon_root;
                    }

                    flag <<= 1;
                });
            }
        }

        perm[0] = BlsScalar::from(mask);
        ScalarStrategy::new().perm(&mut perm);
        let poseidon_root = perm[1];

        Self {
            cardinality,
            poseidon_root,
        }
    }
}
