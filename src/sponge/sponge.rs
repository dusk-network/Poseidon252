//! The `Sponge` techniqe in Poseidon allows to hash an unlimited ammount of data
//! into a single `Scalar`.
//!
//! The sponge hash techniqe requires a padding to be applied before the data can
//! be hashed.
//! This is done to avoid hash collitions as stated in the paper of the Poseidon Hash
//! algorithm. See: (https://eprint.iacr.org/2019/458.pdf)[https://eprint.iacr.org/2019/458.pdf].
//!
//! The inputs of the `sponge_hash` are always `Scalar` or need to be capable of being represented
//! as it.
//!
//! The module provides two sponge hash implementations:
//! - Sponge hash using `Scalar` as backend. Which hashes the inputed `Scalar`s and returns a single
//! `Scalar`.
//! - Sponge hash gadget using `dusk_plonk::Variable` as a backend. This techniqe is used/required
//! when you want to proof pre-images of unconstrained data inside of Zero-Knowledge PLONK circuits.
use super::pad::*;
use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use hades252::strategies::*;
use hades252::WIDTH;

/// The `hash` function takes an arbitrary number of Scalars and returns the
/// hash, using the `Hades` ScalarStragegy
pub fn sponge_hash(messages: &[Scalar]) -> Scalar {
    let mut strategy = ScalarStrategy::new();

    let mut words = pad(messages, WIDTH, Scalar::zero(), Scalar::one());
    // If the words len is less than the Hades252 permutation `WIDTH` we directly
    // call the permutation saving useless additions by zero.
    if words.len() == WIDTH {
        strategy.perm(&mut words);
        return words[1];
    }
    // If the words len is bigger than the Hades252 permutation `WIDTH` then we
    // need to collapse the padded limbs. See bottom of pag. 16 of
    // https://eprint.iacr.org/2019/458.pdf
    words
        .chunks(WIDTH)
        .fold(vec![Scalar::zero(); WIDTH], |mut inputs, values| {
            let mut values = values.iter();
            inputs
                .iter_mut()
                .for_each(|input| *input += values.next().unwrap());
            strategy.perm(&mut inputs);
            inputs
        });
    words[1]
}

/// The `hash` function takes an arbitrary number of plonk `Variable`s and returns the
/// hash, using the `Hades` GadgetStragegy
pub fn sponge_hash_gadget(composer: &mut StandardComposer, messages: &[Variable]) -> Variable {
    let padder = composer.zero_var;
    let eom = composer.add_input(Scalar::one());
    let mut words = pad(messages, WIDTH, padder, eom);
    // If the words len is less than the Hades252 permutation `WIDTH` we directly
    // call the permutation saving useless additions by zero.
    if words.len() == WIDTH {
        let mut strategy = GadgetStrategy::new(composer);
        strategy.perm(&mut words);
        return words[1];
    }
    // If the words len is bigger than the Hades252 permutation `WIDTH` then we
    // need to collapse the padded limbs. See bottom of pag. 16 of
    // https://eprint.iacr.org/2019/458.pdf
    words
        .chunks(WIDTH)
        .fold(vec![padder; WIDTH], |mut inputs, values| {
            let mut values = values.iter();
            inputs.iter_mut().for_each(|input| {
                *input = composer.add(
                    (Scalar::one(), *input),
                    (Scalar::one(), *values.next().unwrap()),
                    Scalar::zero(),
                    Scalar::zero(),
                )
            });
            let mut strategy = GadgetStrategy::new(composer);
            strategy.perm(&mut inputs);
            inputs
        });

    words[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_plonk::commitment_scheme::kzg10::PublicParameters;
    use dusk_plonk::fft::EvaluationDomain;
    use merlin::Transcript;

    const CAPACITY: usize = 1 << 12;

    fn poseidon_sponge_params(width: usize) -> (Vec<Scalar>, Scalar) {
        let mut input = vec![Scalar::zero(); width];
        input
            .iter_mut()
            .for_each(|s| *s = Scalar::random(&mut rand::thread_rng()));
        let output = sponge_hash(&input);
        (input, output)
    }

    // Checks that the result of the hades permutation is the same as the one obtained by
    // the sponge gadget
    fn new_composer(width: usize, i: Vec<Scalar>, out: Scalar) -> StandardComposer {
        let mut composer = StandardComposer::new();

        let mut i_var = vec![composer.zero_var; width];
        i.iter().zip(i_var.iter_mut()).for_each(|(i, v)| {
            *v = composer.add_input(*i);
        });

        let o_var = composer.add_input(out);

        // Apply Poseidon Sponge hash to the inputs
        let computed_o_var = sponge_hash_gadget(&mut composer, &i_var);

        // Check that the Gadget sponge hash result = Scalar sponge hash result
        composer.add_gate(
            o_var,
            computed_o_var,
            composer.zero_var,
            Scalar::one(),
            -Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::zero(),
        );

        composer.add_dummy_constraints();
        composer
    }

    #[test]
    fn sponge_gadget_width_3() {
        // Setup OG params.
        let public_parameters = PublicParameters::setup(CAPACITY, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = public_parameters.trim(CAPACITY).unwrap();
        let domain = EvaluationDomain::new(CAPACITY).unwrap();

        // Test with width = 3
        let (i, o) = poseidon_sponge_params(3usize);
        let mut composer = new_composer(3usize, i, o);
        composer.check_circuit_satisfied();
        let mut transcript = Transcript::new(b"testing");
        // Preprocess circuit
        let circuit = composer.preprocess(&ck, &mut transcript, &domain);

        // Prove
        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());

        // Verify
        assert!(proof.verify(
            &circuit,
            &mut transcript.clone(),
            &vk,
            &composer.public_inputs()
        ));
    }

    #[test]
    fn sponge_gadget_hades_width() {
        // Setup OG params.
        let public_parameters = PublicParameters::setup(CAPACITY, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = public_parameters.trim(CAPACITY).unwrap();
        let domain = EvaluationDomain::new(CAPACITY).unwrap();

        // Test with width = 5
        let (i, o) = poseidon_sponge_params(WIDTH);
        let mut composer = new_composer(WIDTH, i, o);
        composer.check_circuit_satisfied();
        let mut transcript = Transcript::new(b"testing");
        // Preprocess circuit
        let circuit = composer.preprocess(&ck, &mut transcript, &domain);

        // Prove
        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());

        // Verify
        assert!(proof.verify(
            &circuit,
            &mut transcript.clone(),
            &vk,
            &composer.public_inputs()
        ));
    }

    #[test]
    fn sponge_gadget_width_15() {
        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(CAPACITY * 8, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = public_parameters.trim(CAPACITY * 8).unwrap();
        let domain = EvaluationDomain::new(CAPACITY * 8).unwrap();

        // Test with width = 15
        let (i, o) = poseidon_sponge_params(15usize);
        let mut composer = new_composer(15usize, i, o);
        composer.check_circuit_satisfied();
        let mut transcript = Transcript::new(b"testing");
        // Preprocess circuit
        let circuit = composer.preprocess(&ck, &mut transcript, &domain);

        // Prove
        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());

        // Verify
        assert!(proof.verify(
            &circuit,
            &mut transcript.clone(),
            &vk,
            &composer.public_inputs()
        ));
    }
}
