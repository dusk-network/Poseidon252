[![Build Status](https://travis-ci.com/dusk-network/Poseidon252.svg?branch=master)](https://travis-ci.com/dusk-network/Poseidon252)
[![Repository](https://dusk-network.github.io/Poseidon252/repo-badge.svg)](https://github.com/dusk-network/Poseidon252)
[![Documentation](https://dusk-network.github.io/Poseidon252/badge.svg)](https://dusk-network.github.io/Poseidon252/index.html)

# Poseidon252 
Reference implementation for the Poseidon Hashing algorithm.

#### Reference

[Starkad and Poseidon: New Hash Functions for Zero Knowledge Proof Systems](https://eprint.iacr.org/2019/458.pdf)



This repository has been created so there's a unique library that holds the tools & functions
required to perform Poseidon Hashes.

This hashes heavily rely on the Hades permutation, which is one of the key parts that Poseidon needs in order 
to work. 
This library uses the reference implementation of [Hades252](https://github.com/dusk-network/hades252) which has been
designed & build by the [Dusk-Network team](https://dusk.network/).

**The library provides the two hashing techniques of Poseidon:**

## Sponge Hash
The `Sponge` techniqe in Poseidon allows to hash an unlimited ammount of data
into a single `Scalar`.
The sponge hash techniqe requires a padding to be applied before the data can
be hashed.

This is done to avoid hash collitions as stated in the paper of the Poseidon Hash
algorithm. See: (https://eprint.iacr.org/2019/458.pdf)[https://eprint.iacr.org/2019/458.pdf].
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
`Hades252` as backend.

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
use poseidon252::{StorageScalar, PoseidonAnnotation};
use poseidon252::merkle_proof::merkle_opening_gadget;
use dusk_plonk::prelude::*;
use canonical_host::MemStore;
use kelvin_hamt::{HAMTSearch, NarrowHAMT};

// Generate Composer & Public Parameters
let pub_params =
    PublicParameters::setup(1 << 17, &mut rand::thread_rng()).unwrap();
let (ck, vk) = pub_params.trim(1 << 16).unwrap();
// Generate a tree with random scalars inside.
let mut ptree: PoseidonTree<_, MemStore> = PoseidonTree::new(17);
for i in 0..1024u64 {
    ptree
        .push(StorageScalar(BlsScalar::from(i as u64)))
        .unwrap();
}

for i in [0u64, 567, 1023].iter() {
    let mut gadget_tester = |composer: &mut StandardComposer| {
        // We want to proof that we know the Scalar tied to the key Xusize
        // and that indeed, it is inside the merkle tree.

        // In this case, the key X corresponds to the Scalar(X).
        // We're supposing that we're provided with a Kelvin::Branch to perform
        // the proof.
        let branch = ptree.poseidon_branch(*i).unwrap().unwrap();

        // Get tree root.
        let root = ptree.root().unwrap();

        // Add the proven leaf value to the Constraint System
        let proven_leaf = composer.add_input(BlsScalar::from(*i));

        merkle_opening_gadget(composer, branch, proven_leaf, root);

        // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
        // to zero polynomials.
        composer.add_dummy_constraints();
    };

    // Proving
    let mut prover = Prover::new(b"merkle_opening_tester");
    gadget_tester(prover.mut_cs());
    prover.preprocess(&ck)?;
    let proof = prover.prove(&ck)?;

    // Verify
    let mut verifier = Verifier::new(b"merkle_opening_tester");
    gadget_tester(verifier.mut_cs());
    verifier.preprocess(&ck)?;
    assert!(verifier
        .verify(&proof, &vk, &vec![BlsScalar::zero()])
        .is_ok());
}
```


### Standard Merkle Opening Proof example:
```rust
use poseidon252::{StorageScalar, PoseidonAnnotation};
use poseidon252::merkle_proof::merkle_opening_scalar_verification;
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use canonical_host::MemStore;
use poseidon252::PoseidonTree;

 // Generate a tree with random scalars inside.
let mut ptree: PoseidonTree<_, MemStore> = PoseidonTree::new(17);
for i in 0..1024u64 {
    ptree
        .push(StorageScalar(BlsScalar::from(i as u64)))
        .unwrap();
}

for i in 0..1024u64 {
    // We want to proof that we know the Scalar tied to the key Xusize
    // and that indeed, it is inside the merkle tree.

    // In this case, the key X corresponds to the Scalar(X).
    // We're supposing that we're provided with a Kelvin::Branch to perform
    // the proof.
    let branch = ptree.poseidon_branch(i).unwrap().unwrap();

    // Get tree root.
    let root = ptree.root().unwrap();

    assert!(merkle_opening_scalar_verification(
        branch,
        root,
        BlsScalar::from(i),
    ));
}
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