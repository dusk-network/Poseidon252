#![feature(test)]

use poseidon252::sponge;

use bulletproofs::r1cs::{ConstraintSystem, Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::thread_rng;

use bulletproofs::r1cs::{LinearCombination, R1CSError, R1CSProof, Variable};
use curve25519_dalek::scalar::Scalar;

type ProofResult<T> = Result<T, R1CSError>;
use std::time::Instant;
pub fn prove(
    d: Scalar,
    k: Scalar,
    y_inv: Scalar,
    q: Scalar,
    z_img: Scalar,
    seed: Scalar,
    pub_list: Vec<Scalar>,
    toggle: usize,
) -> ProofResult<(
    R1CSProof,
    Vec<CompressedRistretto>,
    Vec<CompressedRistretto>,
)> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(4096, 1);

    let mut transcript = Transcript::new(b"BlindBidProofGadget");

    // 1. Create a prover
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let mut blinding_rng = rand::thread_rng();

    let (commitments, vars): (Vec<_>, Vec<_>) = [d, k, y_inv]
        .iter()
        .map(|v| prover.commit(*v, Scalar::random(&mut blinding_rng)))
        .unzip();

    let (t_c, t_v): (Vec<_>, Vec<_>) = (0..pub_list.len())
        .map(|x| {
            prover.commit(
                Scalar::from((x == toggle) as u8),
                Scalar::random(&mut thread_rng()),
            )
        })
        .unzip();

    // public list of numbers
    let l_v: Vec<LinearCombination> = pub_list.iter().map(|&x| x.into()).collect::<Vec<_>>();

    println!("Proving");
    let start = Instant::now();

    // 3. Build a CS
    proof_gadget(
        &mut prover,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        q.into(),
        z_img.into(),
        seed.into(),
        t_v,
        l_v,
    );

    // 4. Make a proof
    let proof = prover.prove(&bp_gens)?;

    let end = start.elapsed();
    println!("Proving time is {:?}", end);

    Ok((proof, commitments, t_c))
}

pub fn verify(
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
    t_c: Vec<CompressedRistretto>,
    seed: Scalar,
    pub_list: Vec<Scalar>,
    q: Scalar,
    z_img: Scalar,
) -> ProofResult<()> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(4096, 1);
    let mut rng = rand::thread_rng();

    // Verifier logic

    let mut transcript = Transcript::new(b"BlindBidProofGadget");

    // 1. Create a verifier
    let mut verifier = Verifier::new(&mut transcript);

    // 2. Commit high-level variables
    let vars: Vec<_> = commitments.iter().map(|v| verifier.commit(*v)).collect();

    let t_c_v: Vec<Variable> = t_c.iter().map(|v| verifier.commit(*v).into()).collect();

    // public list of numbers
    let l_v: Vec<LinearCombination> = pub_list
        .iter()
        .map(|&x| Scalar::from(x).into())
        .collect::<Vec<_>>();

    println!("Verifying");
    let start = Instant::now();
    // 3. Build a CS
    proof_gadget(
        &mut verifier,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        q.into(),
        z_img.into(),
        seed.into(),
        t_c_v,
        l_v,
    );

    // 4. Verify the proof
    let res = verifier
        .verify(&proof, &pc_gens, &bp_gens, &mut rng)
        .map_err(|_| R1CSError::VerificationError);

    let end = start.elapsed();

    println!("Verification time is {:?}", end);
    res
}

pub fn proof_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    d: LinearCombination,
    k: LinearCombination,
    y_inv: LinearCombination,
    q: LinearCombination,
    z_img: LinearCombination,
    seed: LinearCombination,
    toggle: Vec<Variable>, // private: binary list indicating private number is somewhere in list
    items: Vec<LinearCombination>, // public list
) {
    // m = h(k)
    let m = sponge::gadget(cs, &[k]);
    //let m = hash(&[k]).unwrap();

    // x = h(d, m)
    let x = sponge::gadget(cs, &[d.clone(), m.clone()]);

    one_of_many_gadget(cs, x.clone(), toggle, items);

    // y = h(seed, x)
    let y = sponge::gadget(cs, &[seed.clone(), x]);

    // z = h(seed, m)
    let z = sponge::gadget(cs, &[seed, m]);

    cs.constrain(z_img.clone() - z);

    // // Prove Q
    score_gadget(cs, d, y, y_inv, q);
}

fn score_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    d: LinearCombination,
    y: LinearCombination,
    y_inv: LinearCombination,
    q: LinearCombination,
) {
    let one = Scalar::one();

    // check that Yinv * Y = 1
    let (_, _, one_var) = cs.multiply(y, y_inv.clone());
    cs.constrain(one_var - one);

    // Q = F(d,Y)
    let (_, _, q_var) = cs.multiply(d, y_inv);
    cs.constrain(q - q_var);
}

fn one_of_many_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: LinearCombination,          // private: our item x
    toggle: Vec<Variable>,         // private: binary list indicating it is somewhere in list
    items: Vec<LinearCombination>, // public list
) {
    let toggle_len = toggle.len();

    // ensure every item in toggle is binary
    for i in toggle.iter() {
        boolean_gadget(cs, i.clone().into());
    }

    // toggle_sum[i] = toggle_sum(i-1) + toggle(i)
    let mut toggle_sum: Vec<LinearCombination> = Vec::with_capacity(toggle_len);
    toggle_sum.push(toggle[0].clone().into());
    for i in 1..toggle_len {
        let prev_toggle_sum = toggle_sum[i - 1].clone();
        let curr_toggle = toggle[i].clone();

        toggle_sum.push(prev_toggle_sum + (curr_toggle.clone()));
    }

    // ensure sum of toggles = 1
    for i in 1..toggle_len {
        let prev_toggle_sum = toggle_sum[i - 1].clone();
        let curr_toggle = toggle[i].clone();
        let curr_toggle_sum = toggle_sum[i].clone();

        toggle_sum[i] = toggle_sum[i - 1].clone() + (toggle[i].clone());

        cs.constrain(prev_toggle_sum + (curr_toggle) - (curr_toggle_sum));
    }
    let one: Scalar = Scalar::one();
    let last_item = toggle_sum[toggle_len - 1].clone();
    cs.constrain(last_item - one);

    // now check if item is in list
    // item[i] * toggle[i] = toggle[i] * our item (x)
    for i in 0..toggle_len {
        let (_, _, left) = cs.multiply(items[i].clone(), toggle[i].clone().into());
        let (_, _, right) = cs.multiply(toggle[i].clone().into(), x.clone());
        cs.constrain(left - right);
    }
}

fn boolean_gadget<CS: ConstraintSystem>(cs: &mut CS, a1: LinearCombination) {
    // a *(1-a) = 0
    let a = a1.clone();
    let one: LinearCombination = Scalar::one().into();
    let (_, _, c_var) = cs.multiply(a, one - a1);
    cs.constrain(c_var.into());
}

use rand_core::{OsRng, RngCore};

#[test]
fn test_prove_verify() {
    let mut csprng = OsRng;

    let k: Scalar = Scalar::random(&mut csprng);
    let m = calc_m(k);

    let d: Scalar = Scalar::random(&mut csprng);
    let bid: Scalar = calc_x(d, m);

    let seed: Scalar = Scalar::random(&mut csprng);
    let y: Scalar = calc_y(seed, bid);
    let y_inv: Scalar = y.invert();

    let q: Scalar = y_inv * d;

    let z_img: Scalar = calc_z(seed, m);

    let bid_list_size = 5;
    let secret_bid_position = 3;
    let bid_list = rand_bid_list(bid_list_size, bid, secret_bid_position);

    let (proof, commitments, t_c) = prove(
        d,
        k,
        y_inv,
        q,
        z_img,
        seed,
        bid_list.clone(),
        secret_bid_position,
    )
    .unwrap();

    verify(proof, commitments, t_c, seed, bid_list, q, z_img).unwrap();
}

fn calc_x(d: Scalar, m: Scalar) -> Scalar {
    sponge::hash(&[d, m])
}

fn calc_y(seed: Scalar, x: Scalar) -> Scalar {
    sponge::hash(&[seed, x])
}

fn calc_m(k: Scalar) -> Scalar {
    sponge::hash(&[k])
}

fn calc_z(seed: Scalar, m: Scalar) -> Scalar {
    sponge::hash(&[seed, m])
}

fn rand_bid_list(size: usize, secret_bid: Scalar, insert_at: usize) -> Vec<Scalar> {
    assert!(insert_at < size);

    let mut bid_list: Vec<Scalar> = Vec::with_capacity(size);
    for i in 0..size {
        if insert_at == i {
            bid_list.push(secret_bid);
            continue;
        }

        let x_i: Scalar = Scalar::from(OsRng.next_u64());
        bid_list.push(x_i);
    }

    assert!(bid_list[insert_at] == secret_bid);

    bid_list
}
