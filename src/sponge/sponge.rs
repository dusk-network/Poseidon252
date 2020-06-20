//! The `pad` module implements the Sponge's padding algorithm
use super::pad::*;

use dusk_bls12_381::Scalar;
use dusk_plonk::constraint_system::{StandardComposer, Variable};
use hades252::strategies::*;
use hades252::WIDTH;

/// The `hash` function takes an arbitrary number of Scalars and returns the
/// hash, using the `Hades` ScalarStragegy
pub fn sponge_hash(messages: &[Scalar]) -> Scalar {
    let mut strategy = ScalarStrategy::new();

    // The value used to pad the words is zero.
    let padder = Scalar::zero();
    // One will identify the end of messages.
    let eom = Scalar::one();

    let mut words = pad(messages, WIDTH, padder, eom);
    // If the words len is less than the Hades252 permutation `WIDTH` we directly
    // call the permutation saving useless additions by zero.
    if words.len() == WIDTH {
        strategy.perm(&mut words);
        return words[1];
    }
    // If the words len is bigger than the Hades252 permutation `WIDTH` then we
    // need to collapse the padded limbs. See bottom of pag. 16 of
    // https://eprint.iacr.org/2019/458.pdf
    words.chunks(WIDTH).fold(
        vec![Scalar::zero(); WIDTH],
        |mut inputs, values| {
            let mut values = values.iter();
            inputs
                .iter_mut()
                .for_each(|input| *input += values.next().unwrap());
            strategy.perm(&mut inputs);
            inputs
        },
    );
    words[1]
}

/// The `hash` function takes an arbitrary number of plonk `Variable`s and returns the
/// hash, using the `Hades` GadgetStragegy
pub fn sponge_hash_gadget(
    composer: &mut StandardComposer,
    messages: &[Variable],
) -> Variable {
    // The value used to pad the words is zero.
    let padder = composer.zero_var;
    // One will identify the end of messages.
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
    use bench_utils::*;
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
    fn new_composer(
        width: usize,
        i: Vec<Scalar>,
        out: Scalar,
    ) -> StandardComposer {
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
        let public_parameters =
            PublicParameters::setup(CAPACITY, &mut rand::thread_rng()).unwrap();
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
        // To run the benches run: `cargo test sponge_gadget_hades_width --release --features print-trace -- --nocapture`
        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(CAPACITY, &mut rand::thread_rng()).unwrap();
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
        let init_time =
            start_timer!(|| { "Sponge Gadget Proof Hades252 WIDTH" });
        // Prove
        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());
        end_timer!(init_time);

        // Verify
        assert!(proof.verify(
            &circuit,
            &mut transcript.clone(),
            &vk,
            &composer.public_inputs()
        ));
    }

    #[test]
    fn sponge_gadget_width_x() {
        // To run the benches run: `cargo test sponge_gadget_width_x --release --features print-trace -- --nocapture`
        // Edit the `new_composer` & `poseidon_sponge_params` to the value you want to bench.

        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(CAPACITY * 8, &mut rand::thread_rng())
                .unwrap();
        let (ck, vk) = public_parameters.trim(CAPACITY * 8).unwrap();
        let domain = EvaluationDomain::new(CAPACITY * 8).unwrap();

        // Test with width = 15
        let (i, o) = poseidon_sponge_params(15usize);
        let mut composer = new_composer(15usize, i, o);
        composer.check_circuit_satisfied();
        let mut transcript = Transcript::new(b"testing");
        // Preprocess circuit
        let circuit = composer.preprocess(&ck, &mut transcript, &domain);

        let init_time =
            start_timer!(|| { "Sponge Gadget Proof for 15 inputs" });
        // Prove
        let proof = composer.prove(&ck, &circuit, &mut transcript.clone());
        end_timer!(init_time);
        // Verify
        assert!(proof.verify(
            &circuit,
            &mut transcript.clone(),
            &vk,
            &composer.public_inputs()
        ));
    }
}
