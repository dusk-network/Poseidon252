// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "merkle_tree")]

use dusk_plonk::prelude::*;
use dusk_poseidon::merkle::hash as merkle_hash;
use dusk_poseidon::merkle::tree::{opening_gadget, Item, Opening, Tree};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

// set max circuit size to 2^12 gates
const CAPACITY: usize = 12;

// set height and arity of the poseidon merkle test tree
const HEIGHT: usize = 4;
const ARITY: usize = 4;

type PoseidonItem = Item<()>;

// Create a circuit for the opening
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct OpeningCircuit {
    opening: Opening<(), HEIGHT, ARITY>,
    leaf: PoseidonItem,
}

impl Default for OpeningCircuit {
    fn default() -> Self {
        let mut tree = Tree::new();
        let leaf = PoseidonItem::new(BlsScalar::zero(), ());
        tree.insert(0, leaf);
        let opening = tree.opening(0).expect("There is a leaf at position 0");
        Self { opening, leaf }
    }
}

impl OpeningCircuit {
    /// Create a new OpeningCircuit
    pub fn new(
        opening: Opening<(), HEIGHT, ARITY>,
        leaf: PoseidonItem,
    ) -> Self {
        Self { opening, leaf }
    }
}

impl Circuit for OpeningCircuit {
    fn circuit<C>(&self, composer: &mut C) -> Result<(), Error>
    where
        C: Composer,
    {
        // append the leaf and opening gadget to the circuit
        let leaf = composer.append_witness(self.leaf.hash);
        let computed_root = opening_gadget(composer, &self.opening, leaf);

        // append the public root as public input to the circuit
        // and ensure it is equal to the computed root
        let constraint = Constraint::new()
            .left(-BlsScalar::one())
            .a(computed_root)
            .public(self.opening.root().hash);
        composer.append_gate(constraint);

        Ok(())
    }
}

#[test]
fn test_opening_gadget() {
    let label = b"merkle opening";
    let rng = &mut StdRng::seed_from_u64(0xdea1);
    let pp = PublicParameters::setup(1 << CAPACITY, rng).unwrap();

    let (prover, verifier) = Compiler::compile::<OpeningCircuit>(&pp, label)
        .expect("Circuit should compile successfully");

    let mut tree = Tree::new();
    let mut leaf = PoseidonItem::new(BlsScalar::zero(), ());
    let mut position = 0;
    for _ in 0..100 {
        position = rng.next_u64() % u8::MAX as u64;
        let hash = merkle_hash(&[BlsScalar::from(position)]);
        leaf = PoseidonItem::new(hash, ());
        tree.insert(position as u64, leaf);
    }
    let opening = tree.opening(position as u64).unwrap();
    assert!(opening.verify(leaf.clone()));

    let circuit = OpeningCircuit::new(opening, leaf);

    let (proof, public_inputs) = prover
        .prove(rng, &circuit)
        .expect("Proof generation should succeed");

    verifier
        .verify(&proof, &public_inputs)
        .expect("Proof verification should succeed");
}
