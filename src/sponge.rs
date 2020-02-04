/// The `pad` module implements the Sponge's padding algorithm
pub mod pad;
use pad::*;

use bulletproofs::r1cs::{ConstraintSystem, LinearCombination};
use curve25519_dalek::scalar::Scalar;
use hades252::strategies::*;
use hades252::WIDTH;

/// The `hash` function takes an arbitrary number of Scalars and returns the
/// hash, using the `Hades` stragegy
pub fn hash(messages: &[Scalar]) -> Scalar {
    let mut strategy = ScalarStrategy {};

    let words = pad(messages, WIDTH).chunks(WIDTH).fold(
        vec![Scalar::zero(); WIDTH],
        |mut inputs, values| {
            let mut values = values.iter();
            inputs
                .iter_mut()
                .for_each(|input| *input += values.next().unwrap());
            strategy.perm(inputs)
        },
    );

    words[1]
}

/// The `gadget` function uses the `Hades` strategy in a `ConstraingSystem` context
pub fn gadget(cs: &mut dyn ConstraintSystem, messages: &[LinearCombination]) -> LinearCombination {
    let mut strategy = GadgetStrategy::new(cs);
    let words = pad(messages, WIDTH).chunks(WIDTH).fold(
        vec![LinearCombination::from(Scalar::zero()); WIDTH],
        |mut inputs, values| {
            let mut values = values.iter();
            inputs
                .iter_mut()
                .for_each(|input| *input = input.clone() + values.next().unwrap().clone());
            strategy.perm(inputs)
        },
    );

    words[1].clone()
}
