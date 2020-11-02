use anyhow::Result;
use canonical::Canon;
use canonical_derive::Canon;
use canonical_host::MemStore;
use core::borrow::Borrow;
use dusk_plonk::prelude::*;
use poseidon252::tree::{PoseidonLeaf, PoseidonMaxAnnotation, PoseidonTree};

#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon)]
struct MockLeaf {
    s: BlsScalar,
    expiration: u64,
}

impl From<u64> for MockLeaf {
    fn from(n: u64) -> MockLeaf {
        MockLeaf {
            s: BlsScalar::from(n),
            expiration: n / 3,
        }
    }
}

impl PoseidonLeaf<MemStore> for MockLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        self.s
    }
}

impl Borrow<u64> for MockLeaf {
    fn borrow(&self) -> &u64 {
        &self.expiration
    }
}

fn main() {
    let mut tree: PoseidonTree<MockLeaf, PoseidonMaxAnnotation, MemStore, 17> =
        PoseidonTree::new();
    let mut v = vec![];
    let max = 4097;

    for i in 0..max {
        let s = MockLeaf::from(i as u64);
        let pos = tree.push(s).unwrap();
        assert_eq!(i, pos);
        v.push(s);
    }

    let tree_p = tree.clone();
    let mut walk = tree_p.iter_walk(1).unwrap();
    println!("SomeIteration: {:?}", walk.next().unwrap().unwrap());
    println!("SomeIteration: {:?}", walk.next().unwrap().unwrap());
    println!("SomeIteration: {:?}", walk.next().unwrap().unwrap());
    println!("SomeIteration: {:?}", walk.next().unwrap().unwrap());
    println!("SomeIteration: {:?}", walk.next().unwrap().unwrap());

    println!("{:?}", tree.get(2).unwrap().unwrap());
    println!("{:?}", tree.get(3).unwrap().unwrap());

    v.iter().enumerate().for_each(|(i, s)| {
        let l = tree.get(i).unwrap().unwrap();
        assert_eq!(s, &l);
    });

    v.into_iter().rev().for_each(|s| {
        let t = tree.pop().unwrap().unwrap();
        assert_eq!(s, t);
    });
}
