use canonical::Canon;
use canonical_derive::Canon;
use canonical_host::MemStore;
use core::borrow::Borrow;
use dusk_bls12_381::BlsScalar;
use hades252::{ScalarStrategy, Strategy};
use poseidon252::tree::{
    PoseidonAnnotation, PoseidonLeaf, PoseidonMaxAnnotation, PoseidonTree,
};

#[derive(
    Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon,
)]
pub struct MockLeaf {
    s: BlsScalar,
    pub pos: u64,
    pub expiration: u64,
}

impl From<u64> for MockLeaf {
    fn from(n: u64) -> MockLeaf {
        MockLeaf {
            s: BlsScalar::from(n),
            pos: 0,
            expiration: n / 3,
        }
    }
}

impl PoseidonLeaf<MemStore> for MockLeaf {
    fn poseidon_hash(&self) -> BlsScalar {
        self.s
    }

    fn pos(&self) -> u64 {
        self.pos
    }

    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

impl Borrow<u64> for MockLeaf {
    fn borrow(&self) -> &u64 {
        &self.expiration
    }
}

fn main() {
    const DEPTH: usize = 17;

    let mut h = ScalarStrategy::new();
    let zero = [BlsScalar::zero(); hades252::WIDTH];
    let mut perm = zero;

    [
        1, //, 2, 3, 4, 5, 8, 16, 32, 64, 128, 256, 512, 1023, 1024, 1025,
    ]
    .iter()
    .for_each(|w| {
        let w = *w;

        let mut tree: PoseidonTree<
            MockLeaf,
            PoseidonAnnotation,
            MemStore,
            DEPTH,
        > = PoseidonTree::new();

        for i in 0..w {
            let l = MockLeaf::from(i as u64);
            tree.push(l).unwrap();
        }

        for i in 0..w {
            let root = tree.root().unwrap();
            let branch = tree.branch(i).unwrap().unwrap();
            let leaf = *branch;

            branch.as_ref().iter().for_each(|l| println!("{:?}", l));
            assert_eq!(BlsScalar::from(i as u64), leaf);

            let root_p = branch.as_ref().iter().take(DEPTH).fold(
                leaf,
                |needle, level| {
                    assert_eq!(needle, **level);

                    perm.copy_from_slice(level.as_ref());
                    h.perm(&mut perm);

                    perm[1]
                },
            );

            assert_eq!(root, root_p);
        }
    });
}
