use crate::merkle_proof::poseidon_branch::PoseidonLevel;
use crate::ARITY;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use hades252::strategies::*;
use hades252::WIDTH;

/// The `poseidon_hash` function takes a Merkle Tree Level with up to `ARITY`
/// leaves and applies the poseidon hash, using the `hades252::ScalarStragegy` and
/// computing the corresponding bitflags.
pub fn merkle_level_hash(leaves: &[Option<Scalar>]) -> Scalar {
    let mut strategy = ScalarStrategy::new();
    let mut accum = 0u64;
    let mut res = [Scalar::zero(); WIDTH];
    leaves
        .iter()
        .enumerate()
        .zip(res.iter_mut().skip(1))
        .for_each(|((idx, l), r)| match l {
            Some(scalar) => {
                *r = *scalar;
                accum += 1u64 << ((ARITY - 1) - idx);
            }
            None => *r = Scalar::zero(),
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
pub fn merkle_level_hash_gadget(
    composer: &mut StandardComposer,
    leaves: &[Option<Variable>],
) -> Variable {
    let mut accum = 0u64;
    let mut res = [composer.zero_var; WIDTH];
    leaves
        .iter()
        .zip(res.iter_mut().skip(1))
        .enumerate()
        .for_each(|(idx, (l, r))| match l {
            Some(var) => {
                *r = *var;
                accum += 1u64 << ((ARITY - 1) - idx);
            }
            None => *r = composer.zero_var,
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;

    fn gen_random_merkle_level() -> ([Option<Scalar>; ARITY], Scalar) {
        let mut input = [Some(Scalar::zero()); ARITY];
        input
            .iter_mut()
            .for_each(|s| *s = Some(Scalar::random(&mut rand::thread_rng())));
        // Set to None a leave
        input[2] = None;
        // Compute the level hash
        let output = merkle_level_hash(&input);
        (input, output)
    }

    #[test]
    fn test_merkle_level_bitflags() {
        // Get the inputs and the merkle level hash output
        let (leaves, expected_hash) = gen_random_merkle_level();

        // According to the gen_random_merkle_level, our level will have
        // the following: [Some(leaf), Some(leaf), None, Some(leaf)]
        //
        // This means having a bitflags = 1101 = Scalar::from(13u64).
        // So we will compute the hash without the bitflags requirement
        // already providing it. And it should match the expected one.
        let level = PoseidonLevel {
            leaves: [
                // Set the bitflags we already expect
                Scalar::from(13u64),
                // Set the rest of the values as the leaf or zero
                leaves[0].unwrap_or(Scalar::zero()),
                leaves[1].unwrap_or(Scalar::zero()),
                leaves[2].unwrap_or(Scalar::zero()),
                leaves[3].unwrap_or(Scalar::zero()),
            ],
            // We don't care about this in this specific functionallity test.
            upper_lvl_hash: 0usize,
        };
        let obtained_hash = merkle_level_hash_without_bitflags(&level);

        assert_eq!(obtained_hash, expected_hash);
    }

    #[test]
    fn test_merkle_level_gadget_bitflags() {
        // Gen Public Params and Keys.
        let pub_params = PublicParameters::setup(1 << 12, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = pub_params.trim(1 << 11).unwrap();
        let mut transcript = Transcript::new(b"Test");

        // Generate input merkle level
        let (level_sacalars, expected_hash) = gen_random_merkle_level();

        // Generate a composer
        let mut composer = StandardComposer::new();

        // Get the leafs as Variable and add the bitflags that
        // According to the gen_random_merkle_level, our level will have
        // the following: [Some(leaf), Some(leaf), None, Some(leaf)]
        //
        // This means having a bitflags = 1101 = Variable(Scalar::from(13u64)).
        // So we will compute the hash without the bitflags requirement
        // already providing it. And it should match the expected one.
        let mut leaves = [
            // Set the bitflags we already expect
            composer.add_input(Scalar::from(13u64)),
            // Set the rest of the values as the leaf or zero
            composer.add_input(level_sacalars[0].unwrap_or(Scalar::zero())),
            composer.add_input(level_sacalars[1].unwrap_or(Scalar::zero())),
            composer.add_input(level_sacalars[2].unwrap_or(Scalar::zero())),
            composer.add_input(level_sacalars[3].unwrap_or(Scalar::zero())),
        ];

        let obtained_hash = merkle_level_hash_gadget_without_bitflags(&mut composer, &mut leaves);
        let expected_hash = composer.add_input(expected_hash);
        // Check with an assert_equal gate that the hash computed is indeed correct.
        composer.assert_equal(obtained_hash, expected_hash);

        // Since we don't use all of the wires, we set some dummy constraints to avoid Committing
        // to zero polynomials.
        composer.add_dummy_constraints();

        let prep_circ =
            composer.preprocess(&ck, &mut transcript, &EvaluationDomain::new(2048).unwrap());

        let proof = composer.prove(&ck, &prep_circ, &mut transcript.clone());
        assert!(proof.verify(&prep_circ, &mut transcript, &vk, &vec![Scalar::zero()]));
    }
}
