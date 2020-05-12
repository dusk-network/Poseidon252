use crate::merkle_proof::poseidon_branch::PoseidonLevel;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use hades252::strategies::*;
use hades252::WIDTH;

/// The `poseidon_hash` function takes a Merkle Tree Level with up to `ARITY`
/// leaves and applies the poseidon hash, using the `hades252::ScalarStragegy` and
/// computing the corresponding bitflags.
pub fn merkle_level_hash(leaves: &[Scalar]) -> Scalar {
    let mut strategy = ScalarStrategy::new();
    let mut accum = 0u64;
    let mut res = [Scalar::zero(); WIDTH];
    leaves
        .iter()
        .zip(res.iter_mut().skip(1))
        .enumerate()
        .for_each(|(idx, (l, r))| {
            *r = *l;
            accum += 1u64 << idx;
        });
    // Set bitflags as first element.
    res[0] = Scalar::from(accum);
    strategy.perm(&mut res);
    res[1]
}

/// The `poseidon_hash` function takes a `PoseidonLevel` which has already computed
/// the bitflags and hashes it returning the resulting `Scalar`.
pub(crate) fn merkle_level_hash_without_bitflags(poseidon_level: &PoseidonLevel) -> Scalar {
    let mut strategy = ScalarStrategy::new();
    let mut res = poseidon_level.leaves.clone();
    strategy.perm(&mut res);
    res[1]
}

/// The `poseidon_hash` function takes a Merkle Tree level with up to `ARITY`
/// leaves and applies the poseidon hash, using the `hades252::GadgetStragegy` and
/// computing the corresponding bitflags.
pub fn merkle_level_hash_gadget(composer: &mut StandardComposer, leaves: &[Variable]) -> Variable {
    let mut accum = 0u64;
    let mut res = [composer.zero_var; WIDTH];
    leaves
        .iter()
        .zip(res.iter_mut().skip(1))
        .enumerate()
        .for_each(|(idx, (l, r))| {
            *r = *l;
            accum += 1u64 << idx;
        });
    // Set bitflags as first element.
    res[0] = composer.add_input(Scalar::from(accum));
    let mut strategy = GadgetStrategy::new(composer);
    strategy.perm(&mut res);
    res[1]
}

/// The `poseidon_hash` function takes a Merkle Tree level which has
/// already computed the bitflags term and applies the poseidon hash,
/// using the `hades252::GadgetStragegy` returning the resulting `Variable`.
pub fn merkle_level_hash_gadget_without_bitflags(
    composer: &mut StandardComposer,
    leaves: &mut [Variable; WIDTH],
) -> Variable {
    let mut strategy = GadgetStrategy::new(composer);
    strategy.perm(leaves);
    leaves[1]
}
