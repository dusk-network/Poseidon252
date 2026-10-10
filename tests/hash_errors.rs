// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_poseidon::{Domain, Error, Hash};

const INPUT: [BlsScalar; 4] = [
    BlsScalar::from_raw([1, 0, 0, 0]),
    BlsScalar::from_raw([2, 0, 0, 0]),
    BlsScalar::from_raw([3, 0, 0, 0]),
    BlsScalar::from_raw([4, 0, 0, 0]),
];

// Assert that both fallible finalize functions return `expected`.
fn assert_finalize_err(hash: &Hash, expected: Error) {
    assert_eq!(hash.try_finalize(), Err(expected));
    assert_eq!(hash.try_finalize_truncated(), Err(expected));
}

// Assert that both fallible digest functions return `expected`.
fn assert_digest_err(domain: Domain, input: &[BlsScalar], expected: Error) {
    assert_eq!(Hash::try_digest(domain, input), Err(expected));
    assert_eq!(Hash::try_digest_truncated(domain, input), Err(expected));
}

#[test]
fn no_input() {
    for domain in [Domain::Other, Domain::Encryption] {
        assert_finalize_err(&Hash::new(domain), Error::InvalidIOPattern);
    }
    for domain in [Domain::Merkle2, Domain::Merkle4] {
        assert_finalize_err(&Hash::new(domain), Error::IOPatternViolation);
    }
}

#[test]
fn empty_digest_input() {
    for domain in [Domain::Other, Domain::Encryption] {
        assert_digest_err(domain, &[], Error::InvalidIOPattern);
    }
    for domain in [Domain::Merkle2, Domain::Merkle4] {
        assert_digest_err(domain, &[], Error::IOPatternViolation);
    }
}

#[test]
fn only_empty_chunk() {
    for domain in [Domain::Other, Domain::Encryption] {
        let mut hash = Hash::new(domain);
        hash.update(&[]);
        assert_finalize_err(&hash, Error::InvalidIOPattern);
    }
}

#[test]
fn empty_chunk_next_to_non_empty_chunks() {
    for domain in [Domain::Other, Domain::Encryption] {
        // empty chunk first
        let mut hash = Hash::new(domain);
        hash.update(&[]);
        hash.update(&INPUT[..2]);
        assert_finalize_err(&hash, Error::InvalidIOPattern);

        // empty chunk between non-empty chunks
        let mut hash = Hash::new(domain);
        hash.update(&INPUT[..2]);
        hash.update(&[]);
        hash.update(&INPUT[2..]);
        assert_finalize_err(&hash, Error::InvalidIOPattern);

        // empty chunk last
        let mut hash = Hash::new(domain);
        hash.update(&INPUT[..2]);
        hash.update(&[]);
        assert_finalize_err(&hash, Error::InvalidIOPattern);
    }
}

#[test]
fn empty_chunk_with_valid_merkle_arity() {
    let mut hash = Hash::new(Domain::Merkle2);
    hash.update(&INPUT[..2]);
    hash.update(&[]);
    assert_finalize_err(&hash, Error::InvalidIOPattern);

    let mut hash = Hash::new(Domain::Merkle4);
    hash.update(&INPUT[..2]);
    hash.update(&[]);
    hash.update(&INPUT[2..]);
    assert_finalize_err(&hash, Error::InvalidIOPattern);
}

#[test]
fn output_len_above_limit() {
    const MAX_LEN: usize = u32::MAX as usize >> 1;

    let mut hash = Hash::new(Domain::Other);
    hash.update(&INPUT);
    hash.output_len(MAX_LEN + 1);
    assert_finalize_err(&hash, Error::InvalidIOPattern);
}

#[test]
fn merkle_arity_checked_before_empty_chunk() {
    let mut hash = Hash::new(Domain::Merkle4);
    hash.update(&INPUT[..2]);
    hash.update(&[]);
    assert_finalize_err(&hash, Error::IOPatternViolation);
}

#[test]
fn merkle_arity_mismatch() {
    for (domain, input) in [
        (Domain::Merkle2, &INPUT[..1]),
        (Domain::Merkle2, &INPUT[..3]),
        (Domain::Merkle4, &INPUT[..3]),
    ] {
        assert_digest_err(domain, input, Error::IOPatternViolation);

        let mut hash = Hash::new(domain);
        hash.update(input);
        assert_finalize_err(&hash, Error::IOPatternViolation);
    }

    // the arity is checked against the total length of all chunks
    let mut hash = Hash::new(Domain::Merkle4);
    hash.update(&INPUT[..2]);
    hash.update(&INPUT[..3]);
    assert_finalize_err(&hash, Error::IOPatternViolation);
}

#[test]
fn valid_input_matches_panicking_api() {
    for (domain, input) in [
        (Domain::Merkle2, &INPUT[..2]),
        (Domain::Merkle4, &INPUT[..]),
        (Domain::Encryption, &INPUT[..3]),
        (Domain::Other, &INPUT[..3]),
    ] {
        assert_eq!(
            Hash::try_digest(domain, input),
            Ok(Hash::digest(domain, input))
        );
        assert_eq!(
            Hash::try_digest_truncated(domain, input),
            Ok(Hash::digest_truncated(domain, input))
        );
    }

    let mut hash = Hash::new(Domain::Other);
    hash.update(&INPUT[..1]);
    hash.update(&INPUT[1..]);
    hash.output_len(3);
    assert_eq!(hash.try_finalize(), Ok(hash.finalize()));
    assert_eq!(hash.try_finalize_truncated(), Ok(hash.finalize_truncated()));
}

#[test]
#[should_panic(expected = "the hash input should match the io-pattern rules")]
fn digest_panics_on_empty_input() {
    Hash::digest(Domain::Other, &[]);
}

#[test]
#[should_panic(expected = "the hash input should match the io-pattern rules")]
fn finalize_panics_on_empty_chunk() {
    let mut hash = Hash::new(Domain::Other);
    hash.update(&INPUT[..2]);
    hash.update(&[]);
    hash.finalize();
}

#[test]
fn output_len_only_overrides_the_other_domain() {
    // a zero output length is ignored, keeping the default single element
    let mut hash = Hash::new(Domain::Other);
    hash.update(&INPUT);
    hash.output_len(0);
    assert_eq!(hash.try_finalize(), Ok(Hash::digest(Domain::Other, &INPUT)));

    // the merkle and encryption domains always output a single element
    for (domain, input) in [
        (Domain::Merkle2, &INPUT[..2]),
        (Domain::Merkle4, &INPUT[..]),
        (Domain::Encryption, &INPUT[..]),
    ] {
        let mut hash = Hash::new(domain);
        hash.update(input);
        hash.output_len(3);
        assert_eq!(hash.try_finalize(), Ok(Hash::digest(domain, input)));
    }
}
