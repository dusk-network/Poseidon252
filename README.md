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

The `Sponge` technique in Poseidon allows to hash an unlimited amount of data
into a single `Scalar`.
The sponge hash technique requires a padding to be applied before the data can
be hashed.

This is done to avoid hash collisions as stated in the paper of the Poseidon Hash
algorithm. See: <https://eprint.iacr.org/2019/458.pdf>.
The inputs of the `sponge_hash` are always `Scalar` or need to be capable of being represented
as it.

The module provides two sponge hash implementations:

- Sponge hash using `Scalar` as backend. Which hashes the inputted `Scalar`s and returns a single
  `Scalar`.

- Sponge hash gadget using `dusk_plonk::Witness` as a backend. This technique is used/required
  when you want to proof pre-images of unconstrained data inside Zero-Knowledge PLONK circuits.

## Merkle Hash

The Merkle Level Hashing is a technique that Poseidon is optimized-by-design
to perform.
This technique allows us to perform hashes of an entire Merkle Tree using
`Dusk-Hades` as backend.

The technique requires the computation of a `bitflags` element which is always
positioned as the first item of the level when we hash it, and it basically generated
in respect of the presence or absence of a leaf in the tree level.
This allows to prevent hashing collisions.

At the moment, this library is designed and optimized to work only with trees of `ARITY`
up to 4. **That means that trees with a bigger ARITY SHOULD NEVER be used with this lib.**
The module contains the implementation of 4 variants of the same algorithm to support the
majority of the configurations that the user may need:

- Scalar backend for hashing Merkle Tree levels outside ZK-Circuits with two variants:
  One of them computes the bitflags item while the other assumes that it has already been
  computed and placed in the first Level position.

- `dusk_plonk::Witness` backend for hashing Merkle Tree levels inside ZK-Circuits,
  specifically, PLONK circuits. This implementation comes also with two variants;
  One of them computes the bitflags item while the other assumes that it has already been
  computed and placed in the first Level position.

### Zero Knowledge Merkle Opening Proof example:

```rust
use dusk_plonk::error::Error as PlonkError;
use dusk_poseidon::tree::{self, PoseidonBranch, PoseidonLeaf, PoseidonTree};
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};


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

#[derive(Default)]
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
    fn circuit<C>(&self, composer: &mut C) -> Result<(), PlonkError> 
    where 
        C: Composer,
    {
      let leaf: BlsScalar = *self.branch;
      let leaf = composer.append_witness(leaf);
  
      let root = self.branch.root();
      let root = composer.append_witness(*root);
  
      let root_p =
              tree::merkle_opening::<C, DEPTH>(composer, &self.branch, leaf);
  
      composer.assert_equal(root_p, root);
  
      Ok(())
    }
}

// Create a prover and a verifier
let label = b"dusk-network";
let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

let (prover, verifier) =
    Compiler::compile(&pp, label).expect("failed to compile circuit");

// Instantiate a new tree
let mut tree = Tree::default();
let circuit = MerkleOpeningCircuit::random(&mut OsRng, &mut tree);

// Generate a ZK opening proof
let (proof, public_inputs) = prover.prove(&mut OsRng, &circuit)
            .expect("proving the circuit should succeed");

// Verify the proof
verifier.verify(&proof, &public_inputs)
    .expect("verifying the proof should succeed");
```

## Documentation

This crate contains info about all the functions that the library provides as well as the
documentation regarding the data structures that it exports. To check it, please feel free to go to
the [documentation page](https://dusk-network.github.io/Poseidon252/poseidon252/index.html)

## Benchmarks

There are benchmarks for `sponge` and `cipher` in their native form (i.e. as they would run on the host) and their in-circuit form, and benchmarks for the in-circuit `merkle_opening`.

To run all benchmarks on your machine, run
```shell
cargo bench
```
in the repository.

To run a specific benchmark, run
```shell
cargo bench --bench <name>
```
where you replace `<name>` with the benchmark name. For example to run the benchmarks for the poseidon cipher encription from the file 'benches/cipher_encrypt.rs', you would need to run
```shell
cargo bench --benches cipher_encrypt
```

## Licensing

This code is licensed under Mozilla Public License Version 2.0 (MPL-2.0). Please see [LICENSE](https://github.com/dusk-network/plonk/blob/master/LICENSE) for further info.

## About

Implementation designed by the [dusk](https://dusk.network) team.

## Contributing

- If you want to contribute to this repository/project please, check [CONTRIBUTING.md](https://github.com/dusk-network/Poseidon252/blob/master/CONTRIBUTING.md)
- If you want to report a bug or request a new feature addition, please open an issue on this repository.
