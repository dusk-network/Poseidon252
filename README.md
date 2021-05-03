![Build Status](https://github.com/dusk-network/Poseidon252/workflows/Continuous%20integration/badge.svg)
[![Repository](https://img.shields.io/badge/github-poseidon252-blueviolet)](https://github.com/dusk-network/Poseidon252)
[![Documentation](https://img.shields.io/badge/docs-poseidon252-blue)](https://docs.rs/dusk-poseidon/latest/dusk_poseidon/)

# Dusk-Poseidon

Reference implementation for the Poseidon Hashing algorithm.

#### Reference

[Starkad and Poseidon: New Hash Functions for Zero Knowledge Proof Systems](https://eprint.iacr.org/2019/458.pdf)

This repository has been created so there's a unique library that holds the tools & functions
required to perform Poseidon Hashes.

This hashes heavily rely on the Hades permutation, which is one of the key parts that Poseidon needs in order
to work.
This library uses the reference implementation of [Dusk-Hades](https://github.com/dusk-network/hades252) which has been
designed & build by the [Dusk-Network team](https://dusk.network/).

**The library provides the two hashing techniques of Poseidon:**

## Sponge Hash

The `Sponge` techniqe in Poseidon allows to hash an unlimited ammount of data
into a single `Scalar`.
The sponge hash techniqe requires a padding to be applied before the data can
be hashed.

This is done to avoid hash collitions as stated in the paper of the Poseidon Hash
algorithm. See: <https://eprint.iacr.org/2019/458.pdf>.
The inputs of the `sponge_hash` are always `Scalar` or need to be capable of being represented
as it.

The module provides two sponge hash implementations:

- Sponge hash using `Scalar` as backend. Which hashes the inputed `Scalar`s and returns a single
  `Scalar`.

- Sponge hash gadget using `dusk_plonk::Variable` as a backend. This techniqe is used/required
  when you want to proof pre-images of unconstrained data inside of Zero-Knowledge PLONK circuits.

## Merkle Hash

The Merkle Level Hashing is a technique that Poseidon is optimized-by-design
to perform.
This technique allows us to perform hashes of an entire Merkle Tree using
`Dusk-Hades` as backend.

The technique requires the computation of a `bitflags` element which is always
positioned as the first item of the level when we hash it, and it basically generated
in respect of the presence or absence of a leaf in the tree level.
This allows to prevent hashing collitions.

At the moment, this library is designed and optimized to work only with trees of `ARITY`
up to 4. **That means that trees with a bigger ARITY SHOULD NEVER be used with this lib.**
The module contains the implementation of 4 variants of the same algorithm to support the
majority of the configurations that the user may need:

- Scalar backend for hashing Merkle Tree levels outside of ZK-Circuits whith two variants:
  One of them computes the bitflags item while the other assumes that it has already been
  computed and placed in the first Level position.

- `dusk_plonk::Variable` backend for hashing Merkle Tree levels inside of ZK-Circuits,
  specifically, PLONK circuits. This implementation comes also whith two variants;
  One of them computes the bitflags item while the other assumes that it has already been
  computed and placed in the first Level position.

### Zero Knowledge Merkle Opening Proof example:

```rust
#[cfg(feature = "canon")]
{
use canonical_derive::Canon;
use dusk_plonk::prelude::*;
use dusk_poseidon::tree::{PoseidonAnnotation, PoseidonLeaf, PoseidonTree, merkle_opening};
use rand_core::OsRng;

// Constant depth of the merkle tree
const DEPTH: usize = 17;

// Leaf representation
#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Canon)]
struct DataLeaf {
    data: BlsScalar,
    pos: u64,
}

// Example helper
impl From<u64> for DataLeaf {
    fn from(n: u64) -> DataLeaf {
        DataLeaf {
            data: BlsScalar::from(n),
            pos: n,
        }
    }
}

// Any leaf of the poseidon tree must implement `PoseidonLeaf`
impl PoseidonLeaf for DataLeaf {
    // Cryptographic hash of the data leaf
    fn poseidon_hash(&self) -> &BlsScalar {
        &self.data
    }

    // Position on the tree
    fn pos(&self) -> &u64 {
        &self.pos
    }

    // Method used to set the position on the tree after the `PoseidonTree::push` call
    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

fn main() -> Result<(), Error> {
    // Create the ZK keys
    let pub_params = PublicParameters::setup(1 << 15, &mut OsRng)?;
    let (ck, ok) = pub_params.trim(1 << 15)?;

    // Instantiate a new tree
    let mut tree: PoseidonTree<DataLeaf, PoseidonAnnotation, DEPTH> =
        PoseidonTree::new();

    // Append 1024 elements to the tree
    for i in 0..1024 {
        let l = DataLeaf::from(i as u64);
        tree.push(l).unwrap();
    }

    // Create a merkle opening tester gadget
    let gadget_tester =
        |composer: &mut StandardComposer,
         tree: &PoseidonTree<DataLeaf, PoseidonAnnotation, DEPTH>,
         n: usize| {
            let branch = tree.branch(n as u64).unwrap().unwrap();
            let root = tree.root().unwrap();

            let root_p = merkle_opening::<DEPTH>(composer, &branch);
            composer.constrain_to_constant(root_p, BlsScalar::zero(), Some(-root));
        };

    // Define the transcript initializer for the ZK backend
    let label = b"opening_gadget";
    let pos = 0;

    // Create a merkle opening ZK proof
    let mut prover = Prover::new(label);
    gadget_tester(prover.mut_cs(), &tree, pos);
    prover.preprocess(&ck)?;
    let proof = prover.prove(&ck)?;

    // Verify the merkle opening proof
    let mut verifier = Verifier::new(label);
    gadget_tester(verifier.mut_cs(), &tree, pos);
    verifier.preprocess(&ck)?;
    let pi = verifier.mut_cs().construct_dense_pi_vec();
    verifier.verify(&proof, &ok, &pi).unwrap();

    Ok(())
}

}
```

## Canonical

The canonical implementations aim to make available a single representation of the Merkle tree to constrained (referred to as "hosted") and unconstrained (referred to as "host") environments.

For that, we rely on the feature `canon`.

`canon` feature will require all the crates needed for the Merkle tree to function.


## Documentation

This crate contains info about all of the functions that the library provides as well as the
documentation regarding the data structures that it exports. To check it, please feel free to go to
the [documentation page](https://dusk-network.github.io/Poseidon252/poseidon252/index.html)

## Licensing

This code is licensed under Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for further info.

## About

Implementation designed by the [dusk](https://dusk.network) team.

## Contributing

- If you want to contribute to this repository/project please, check [CONTRIBUTING.md](https://github.com/dusk-network/Poseidon252/blob/master/CONTRIBUTING.md)
- If you want to report a bug or request a new feature addition, please open an issue on this repository.
