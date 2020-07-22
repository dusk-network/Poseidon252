//! The `pad` module implements the Sponge's padding algorithm
use super::pad::*;

use dusk_plonk::prelude::*;
use hades252::strategies::*;
use hades252::WIDTH;

/// The `hash` function takes an arbitrary number of Scalars and returns the
/// hash, using the `Hades` ScalarStragegy
pub fn sponge_hash(messages: &[BlsScalar]) -> BlsScalar {
    let mut strategy = ScalarStrategy::new();

    // The value used to pad the words is zero.
    let padder = BlsScalar::zero();
    // One will identify the end of messages.
    let eom = BlsScalar::one();

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
        vec![BlsScalar::zero(); WIDTH],
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
    // Create and constrait one and zero as witnesses.
    let zero = composer.add_input(BlsScalar::zero());
    composer.constrain_to_constant(zero, BlsScalar::zero(), BlsScalar::zero());
    let one = composer.add_input(BlsScalar::one());
    composer.constrain_to_constant(one, BlsScalar::one(), BlsScalar::one());
    // The value used to pad the words is zero.
    let padder = zero;
    // One will identify the end of messages.
    let eom = one;

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
                    (BlsScalar::one(), *input),
                    (BlsScalar::one(), *values.next().unwrap()),
                    BlsScalar::zero(),
                    BlsScalar::zero(),
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

    const CAPACITY: usize = 1 << 12;

    fn poseidon_sponge_params(width: usize) -> (Vec<BlsScalar>, BlsScalar) {
        let mut input = vec![BlsScalar::zero(); width];
        input
            .iter_mut()
            .for_each(|s| *s = BlsScalar::random(&mut rand::thread_rng()));
        let output = sponge_hash(&input);
        (input, output)
    }

    // Checks that the result of the hades permutation is the same as the one obtained by
    // the sponge gadget
    fn sponge_gadget_tester(
        width: usize,
        i: Vec<BlsScalar>,
        out: BlsScalar,
        composer: &mut StandardComposer,
    ) {
        let zero = composer.add_input(BlsScalar::zero());
        composer.constrain_to_constant(
            zero,
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        let mut i_var = vec![zero; width];
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
            zero,
            BlsScalar::one(),
            -BlsScalar::one(),
            BlsScalar::zero(),
            BlsScalar::zero(),
            BlsScalar::zero(),
        );

        composer.add_dummy_constraints();
    }

    #[test]
    fn sponge_gadget_width_3() {
        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(CAPACITY, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = public_parameters.trim(CAPACITY).unwrap();

        // Test with width = 3

        // Proving
        let (i, o) = poseidon_sponge_params(3usize);
        let mut prover = Prover::new(b"sponge_tester");
        sponge_gadget_tester(3usize, i, o, prover.mut_cs());
        prover.preprocess(&ck).expect("Error on preprocessing");
        let proof = prover.prove(&ck).expect("Error on proof generation");

        // Verify
        let mut verifier = Verifier::new(b"sponge_tester");
        sponge_gadget_tester(3usize, i, o, verifier.mut_cs());
        verifier.preprocess(&ck).expect("Error on preprocessing");
        assert!(verifier
            .verify(&proof, &vk, &vec![BlsScalar::zero()])
            .is_ok());
    }

    #[test]
    fn sponge_gadget_hades_width() {
        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(CAPACITY, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = public_parameters.trim(CAPACITY).unwrap();

        // Test with width = 5

        // Proving
        let (i, o) = poseidon_sponge_params(WIDTH);
        let mut prover = Prover::new(b"sponge_tester");
        sponge_gadget_tester(WIDTH, i, o, prover.mut_cs());
        prover.preprocess(&ck).expect("Error on preprocessing");
        let proof = prover.prove(&ck).expect("Error on proof generation");

        // Verify
        let mut verifier = Verifier::new(b"sponge_tester");
        sponge_gadget_tester(WIDTH, i, o, verifier.mut_cs());
        verifier.preprocess(&ck).expect("Error on preprocessing");
        assert!(verifier
            .verify(&proof, &vk, &vec![BlsScalar::zero()])
            .is_ok());
    }

    #[test]
    fn sponge_gadget_width_15() {
        // Setup OG params.
        let public_parameters =
            PublicParameters::setup(CAPACITY, &mut rand::thread_rng()).unwrap();
        let (ck, vk) = public_parameters.trim(CAPACITY).unwrap();

        // Test with width = 15

        // Proving
        let (i, o) = poseidon_sponge_params(15usize);
        let mut prover = Prover::new(b"sponge_tester");
        sponge_gadget_tester(15usize, i, o, prover.mut_cs());
        prover.preprocess(&ck).expect("Error on preprocessing");
        let proof = prover.prove(&ck).expect("Error on proof generation");

        // Verify
        let mut verifier = Verifier::new(b"sponge_tester");
        sponge_gadget_tester(15usize, i, o, verifier.mut_cs());
        verifier.preprocess(&ck).expect("Error on preprocessing");
        assert!(verifier
            .verify(&proof, &vk, &vec![BlsScalar::zero()])
            .is_ok());
    }
}
