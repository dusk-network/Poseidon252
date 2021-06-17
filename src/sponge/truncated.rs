// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Sponge hash and gadget definition

use super::sponge::*;
use dusk_bls12_381::BlsScalar;
use dusk_plonk::prelude::*;

/// The constant represents the bitmask used to truncate the hashing results of a sponge application
/// so that they fit inside of a [`dusk_jubjub::JubJubScalar`] and it's equal to `2^250 - 1`.
///
/// Let the bitmask size be `m`
/// Considering the field size of jubjub is 251 bits, `m < 251`
/// Plonk logical gates will accept only even `m + 1`, so `(m + 1) % 2 == 0`
///
/// Plonk logical gates will perform the operation from the base bls `r` of
/// 255 bits + 1. `d = r + 1 - (m + 1) = 4`. But, `d = 4` don't respect the
/// previously set constraint, so it must be 6.
///
/// This way, the scalar will be truncated to `m = r - d = 255 - 6 = 249
/// bits`
const TRUNCATION_LIMIT: BlsScalar = BlsScalar([
    0x432667a3f7cfca74,
    0x7905486e121a84be,
    0x19c02884cfe90d12,
    0xa62ffba6a1323be,
]);

/// Applies [`sponge_hash`] to the `messages` recieved truncating the result to make it fit
/// inside a `JubJubScalar.`
pub fn hash(messages: &[BlsScalar]) -> JubJubScalar {
    JubJubScalar::from_raw(
        (sponge_hash(messages) & TRUNCATION_LIMIT).reduce().0,
    )
}

/// Mirror the implementation of [`truncate_hash`] inside of a PLONK circuit.
///
/// The circuit will be defined by the length of `messages`. This means that a
/// pre-computed circuit will not behave generically for different messages
/// sizes.
///
/// The expected usage is the length of the message to be known publically as
/// the circuit definition. Hence, the padding value `1` will be appended as a
/// circuit description.
///
/// The returned value is the hashed witness data computed as a variable and truncated
/// to fit inside of a [`JubJubScalar`].
pub fn gadget(
    composer: &mut StandardComposer,
    messages: &[Variable],
) -> Variable {
    let hash_res = sponge_gadget(composer, messages);
    composer.xor_gate(hash_res, composer.zero_var(), 250)
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use dusk_bytes::ParseHexStr;
    use rand_core::OsRng;

    const TEST_INPUTS: [&str; 32] = [
        "bb67ed265bf1db490ded2e1ede55c0d14c55521509dc73f9c354e98ab76c9625",
        "7e74220084d75e10c89e9435d47bb5b8075991b2e29be3b84421dac3b1ee6007",
        "5ce5481a4d78cca03498f72761da1b9f1d2aa8fb300be39f0e4fe2534f9d4308",
        "b1e710e3c4a8c35154b0ce4e4f4af6f498ebd79f8e7cdf3150372c7501be250b",
        "33c9e2025f86b5d82149f1ab8e20a168fc3d99d09b48cbce0286db8752cc3306",
        "e98206bfdce791e4e5144079b997d4fc25006194b35655f0e48490b26e24ea35",
        "86d2a95cc552de8d5bb20bd4a407fee5ffdc314e93dfe6b2dc792bc71fd8cc2d",
        "4edd8307ce28a8c70963d20a7bc28df1e1720bbbc93878a18bd07fad7d51fa15",
        "eabc7a296704a68aa01f95adc85f6dd758b175745336d8fc795a17984024b21e",
        "cfc108673c93df305e31c283b9c767b7097ae4e174a223e0c24b15a67b701a3a",
        "5e9073de60c35dccd19d52a5222616bc89ac677adf1fce33e20a3dcb63b61216",
        "038591e101cb5d60d142574e3abb1a1d9bb8bbf1102bdaefe08cca549b988c1b",
        "e44a54e74c8dd6d468c90dbd9555c8a2468d6161d794a55bd6ff8d7264d5c017",
        "b74f0dac3af5ac492ea46d9087462e990f8ade709037c79b8c6a808f5a9a6c26",
        "4f580037162bbac706d7228b6bd62f4e38032b06734530b818221e37bb1b972f",
        "f5cfbc1185ccb3f0ecadb4ba5630f9260b881c83c924ca1332637df58be5170e",
        "ed1b4cab775e86de9117b5dae0cee7ed75a6f0be8394dc42c3a7502bfb64942c",
        "ce8bcf8952c3daf89ee9fe55ff3acf3bf83c17d28c50fb7fa0db3ce471cc1134",
        "3ee00d2d773237f5f807715894f1a320019c34914b880d4c87299f83de7ece2e",
        "3a1eef3d0a84798020b3016ae323f0c71916074b636c6ca55e53abd859dbd10e",
        "6c4e854816920cc4b34820d6e5d5c4c210125a35289261c42c20beea88375439",
        "8264f7a36717ab6149bd0c7b2a6496e9aa4952fa74f9e20075d712f61e6c3e12",
        "0601f84b745cb0ee65ed275a3913566ca2948e8c7911c4c2f2e34ecaa446f23c",
        "86126b269583662d1ea7c1a9045784dab704c8305218c621483a48aefbd1611c",
        "56d655c6ae6136b9d7b22824999a182acdf68a8a5a5095e586a5c9038b635511",
        "3ff4311953234ce812ef86ec4c0f3bf381a4a9d31a9025813ba69e7e3c19021b",
        "8d9aec8c1b34e5f59ad4633a670e7bede86ef777395c7b14057f28c2c2ae4802",
        "4f47cd90d7f732b7255dceb56084d0889824b66b929bf57255db3e95786f813a",
        "535ac1999b63f38bf718ef12b98dd0f095975244aefc402ac6203878d8f6e93c",
        "e1eb9d629f14b587e6c5eed82aefea704f2968edbb0bedbd906bfa31089f7412",
        "958318907edb1b919a62fd62aeab05e2c6fea95fc731ba169ae8e406aec5361a",
        "e111a0664ac113b960cd336643db4b34c5cd4f69de84d44be95cadaca4d19115",
    ];

    fn truncated_gadget(
        composer: &mut StandardComposer,
        messages: &[BlsScalar],
    ) {
        let truncated_res = hash(messages);
        let final_point = JubJubAffine::from(
            dusk_jubjub::GENERATOR_EXTENDED * &truncated_res,
        );

        // Circuit
        let input_vars: Vec<Variable> = messages
            .iter()
            .map(|message| composer.add_input(*message))
            .collect();
        let truncated_res_var = gadget(composer, &input_vars);
        let point_result = composer.fixed_base_scalar_mul(
            truncated_res_var,
            dusk_jubjub::GENERATOR_EXTENDED,
        );
        composer.assert_equal_public_point(point_result, final_point);
    }

    #[test]
    fn truncation_sponges_match() -> Result<(), Error> {
        // Setup OG params.
        let public_parameters = PublicParameters::setup(1 << 17, &mut OsRng)?;
        let (ck, vk) = public_parameters.trim(1 << 17)?;

        let test_inputs: Vec<BlsScalar> = TEST_INPUTS
            .iter()
            .map(|input| BlsScalar::from_hex_str(input).unwrap())
            .collect();

        let gadget_tester = |messages: &[BlsScalar]| -> Result<(), Error> {
            let mut prover = Prover::new(b"sponge_tester");
            truncated_gadget(prover.mut_cs(), messages);
            let pi = prover.mut_cs().construct_dense_pi_vec().clone();
            prover.preprocess(&ck)?;
            let proof = prover.prove(&ck)?;

            // Verify
            let mut verifier = Verifier::new(b"sponge_tester");
            truncated_gadget(verifier.mut_cs(), messages);
            verifier.preprocess(&ck)?;
            verifier.verify(&proof, &vk, &pi)
        };

        assert!(gadget_tester(&test_inputs[0..3]).is_ok());

        assert!(gadget_tester(&test_inputs[0..6]).is_ok());

        assert!(gadget_tester(&test_inputs[0..9]).is_ok());

        Ok(())
    }
}
