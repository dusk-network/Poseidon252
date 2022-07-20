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

- Sponge hash gadget using `dusk_plonk::Witness` as a backend. This techniqe is used/required
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

- `dusk_plonk::Witness` backend for hashing Merkle Tree levels inside of ZK-Circuits,
  specifically, PLONK circuits. This implementation comes also whith two variants;
  One of them computes the bitflags item while the other assumes that it has already been
  computed and placed in the first Level position.

### Zero Knowledge Merkle Opening Proof example:

```rust
use dusk_plonk::error::Error as PlonkError;
use dusk_poseidon::tree::{self, PoseidonBranch, PoseidonLeaf, PoseidonTree};
use rand_core::{CryptoRng, OsRng, RngCore};

use dusk_plonk::prelude::*;
use nstack::annotation::Keyed;

// Depth of the merkle tree
const DEPTH: usize = 17;

// Capacity of the circuit
const CAPACITY: usize = 15;

// Alias for the default tree implementation
type Tree = PoseidonTree<DataLeaf, (), DEPTH>;

// Leaf representation
#[derive(Debug, Default, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct DataLeaf {
    data: BlsScalar,
    pos: u64,
}

// Keyed needs to be implemented for a leaf type and the tree key.
impl Keyed<()> for DataLeaf {
    fn key(&self) -> &() {
        &()
    }
}

impl DataLeaf {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let data = BlsScalar::random(rng);
        let pos = 0;

        Self { data, pos }
    }
}

// Any leaf of the poseidon tree must implement `PoseidonLeaf`
impl PoseidonLeaf for DataLeaf {
    // Cryptographic hash of the data leaf
    fn poseidon_hash(&self) -> BlsScalar {
        self.data
    }

    // Position on the tree
    fn pos(&self) -> &u64 {
        &self.pos
    }

    // Method used to set the position on the tree after the
    // `PoseidonTree::push` call.
    fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }
}

struct MerkleOpeningCircuit {
    branch: PoseidonBranch<DEPTH>,
}

impl MerkleOpeningCircuit {
    /// Generate N random leaves and append them to the tree
    pub fn random<R: RngCore + CryptoRng>(
        rng: &mut R,
        tree: &mut Tree,
    ) -> Self {
        const N: u64 = 1024;

        // Append 1024 elements to the tree
        for _ in 0..N {
            let leaf = DataLeaf::random(rng);
            tree.push(leaf);
        }

        let branch = tree.branch(N - 1).expect(
            "Failed to fetch the branch of the created leaf from the tree",
        );

        Self { branch }
    }
}

impl Circuit for MerkleOpeningCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        use std::ops::Deref;

        let leaf: BlsScalar = *self.branch.deref();
        let leaf = composer.append_witness(leaf);

        let root = self.branch.root();
        let root = composer.append_witness(*root);

        let root_p =
            tree::merkle_opening::<DEPTH>(composer, &self.branch, leaf);

        composer.assert_equal(root_p, root);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << CAPACITY
    }
}

// Create the ZK keys
let label = b"dusk-network";
let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

// Instantiate a new tree
let mut tree = Tree::default();
let mut circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);
let (pk, vd) = circuit.compile(&pp).expect("Failed to compile circuit");

// Generate a ZK opening proof
let proof = circuit
    .prove(&pp, &pk, label, &mut OsRng)
    .expect("Failed to generate proof");

// Verify the proof
MerkleOpeningCircuit::verify(&pp, &vd, &proof, &[], label)
    .expect("Proof verification failed");
```

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
