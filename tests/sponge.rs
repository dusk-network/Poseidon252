// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::ParseHexStr;
use dusk_plonk::error::Error as PlonkError;
use dusk_poseidon::sponge;
use rand_core::OsRng;

use dusk_plonk::prelude::*;

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

const CAPACITY: usize = 12;

fn poseidon_sponge_params(n: usize) -> (Vec<BlsScalar>, BlsScalar) {
    let mut input = vec![BlsScalar::zero(); n];

    input
        .iter_mut()
        .for_each(|s| *s = BlsScalar::random(&mut OsRng));

    let output = sponge::hash(&input);

    (input, output)
}

#[derive(Debug)]
pub struct TestSpongeCircuit {
    input: Vec<BlsScalar>,
    output: BlsScalar,
}

impl TestSpongeCircuit {
    pub fn new(input: Vec<BlsScalar>, output: BlsScalar) -> Self {
        Self { input, output }
    }
}

impl Circuit for TestSpongeCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        let zero = TurboComposer::constant_zero();

        let mut i_var = vec![zero; self.input.len()];
        self.input.iter().zip(i_var.iter_mut()).for_each(|(i, v)| {
            *v = composer.append_witness(*i);
        });

        // Apply Poseidon Sponge hash to the inputs
        let computed_o_var = sponge::gadget(composer, i_var.as_slice());

        // Check that the Gadget sponge hash result = Scalar sponge hash result
        let o_var = composer.append_witness(self.output);
        composer.assert_equal(o_var, computed_o_var);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << CAPACITY
    }
}

#[test]
fn sponge_gadget() -> Result<(), Error> {
    let label = b"sponge-tester";
    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng)?;

    for w in [3, 5, 15].iter() {
        let w = *w;

        let (pk, vd) = TestSpongeCircuit::new(
            vec![BlsScalar::zero(); w],
            BlsScalar::zero(),
        )
        .compile(&pp)?;

        let (i, o) = poseidon_sponge_params(w);
        let proof = TestSpongeCircuit::new(i, o).prove(&pp, &pk, label)?;

        TestSpongeCircuit::verify(&pp, &vd, &proof, &[], label)?;
    }

    Ok(())
}

#[test]
fn sponge_hash_test() {
    let test_inputs: Vec<BlsScalar> = TEST_INPUTS
        .iter()
        .map(|input| BlsScalar::from_hex_str(input).unwrap())
        .collect();

    assert_eq!(
        "0xe36f4ea9b858d5c85b02770823c7c5d8253c28787d17f283ca348b906dca8528",
        format!("{:#x}", sponge::hash(&test_inputs[..3]))
    );

    assert_eq!(
        "0x75ea3265c80d07e608c1f363ea0b4394ff1fa1cbf50b43b14c880a5755f7f755",
        format!("{:#x}", sponge::hash(&test_inputs[..4]))
    );

    assert_eq!(
        "0x533106a0980eff5b01f5ce63a6b0dd87328b318ac6aa600fc28b9a2ab9f88842",
        format!("{:#x}", sponge::hash(&test_inputs[..5]))
    );

    assert_eq!(
        "0x1a815864684fff47c4d279ee4c31ad964c9dc232734e08188554fa27d33e6731",
        format!("{:#x}", sponge::hash(&test_inputs[..6]))
    );

    assert_eq!(
        "0xa8b936d057df818048e634254719d13970df22926c51e5190c916fcf13dfa25a",
        format!("{:#x}", sponge::hash(&test_inputs[..8]))
    );

    assert_eq!(
        "0x982934231a0410c86f9ed1daa46863a5ddae6d250670d27cb21d10739088e30b",
        format!("{:#x}", sponge::hash(&test_inputs[..10]))
    );
}

#[derive(Debug)]
pub struct TestTruncatedCircuit {
    input: Vec<BlsScalar>,
    output: JubJubScalar,
}

const TRUNCATED_CAPACITY: usize = 17;

impl TestTruncatedCircuit {
    pub fn new(input: Vec<BlsScalar>, output: JubJubScalar) -> Self {
        Self { input, output }
    }
}

impl Circuit for TestTruncatedCircuit {
    const CIRCUIT_ID: [u8; 32] = [0xff; 32];

    fn gadget(
        &mut self,
        composer: &mut TurboComposer,
    ) -> Result<(), PlonkError> {
        let h = sponge::truncated_hash(self.input.as_slice());
        let p = JubJubAffine::from(dusk_jubjub::GENERATOR_EXTENDED * h);
        let p = composer.append_point(p);

        let i: Vec<Witness> = self
            .input
            .iter()
            .map(|i| composer.append_witness(*i))
            .collect();

        let o = composer.append_witness(self.output);

        let t = sponge::truncated_gadget(composer, i.as_slice());
        let p_p = composer
            .component_mul_generator(t, dusk_jubjub::GENERATOR_EXTENDED);

        composer.assert_equal(t, o);
        composer.assert_equal_point(p, p_p);

        Ok(())
    }

    fn public_inputs(&self) -> Vec<PublicInputValue> {
        vec![]
    }

    fn padded_gates(&self) -> usize {
        1 << TRUNCATED_CAPACITY
    }
}

#[test]
fn truncated_sponge() -> Result<(), PlonkError> {
    let input: Vec<BlsScalar> = TEST_INPUTS
        .iter()
        .map(|input| BlsScalar::from_hex_str(input).unwrap())
        .collect();

    let label = b"truncated-sponge-tester";
    let pp = PublicParameters::setup(1 << TRUNCATED_CAPACITY, &mut OsRng)?;

    for w in [3, 6, 9].iter() {
        let w = *w;

        let (pk, vd) = TestTruncatedCircuit::new(
            vec![BlsScalar::zero(); w],
            JubJubScalar::zero(),
        )
        .compile(&pp)?;

        let i = (&input[..w]).to_vec();
        let o = sponge::truncated_hash(i.as_slice());
        let proof = TestTruncatedCircuit::new(i, o).prove(&pp, &pk, label)?;

        TestTruncatedCircuit::verify(&pp, &vd, &proof, &[], label)?;
    }

    Ok(())
}
