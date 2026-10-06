// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubScalar;
use dusk_safe::{Call, Sponge};

use crate::Error;
use crate::hades::ScalarPermutation;

#[cfg(feature = "zk")]
pub(crate) mod gadget;

/// The Domain Separation for Poseidon
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Domain {
    /// Domain to specify hashing of 4-arity merkle tree.
    /// Note that selecting this domain-separator means that the total hash
    /// input must be exactly 4 `BlsScalar` long, and any empty slots of the
    /// merkle tree level need to be filled with the zero element.
    Merkle4,
    /// Domain to specify hashing of 2-arity merkle tree
    /// Note that selecting this domain-separator means that the total hash
    /// input must be exactly 2 `BlsScalar` long, and any empty slots of the
    /// merkle tree level need to be filled with the zero element.
    Merkle2,
    /// Domain to specify hash used for encryption
    Encryption,
    /// Domain to specify hash for any other input
    Other,
}

impl From<Domain> for u64 {
    /// Encryption for the domain-separator are taken from section 4.2 of the
    /// paper adapted to u64.
    /// When `Other` is selected we set the domain-separator to zero. We can do
    /// this since the io-pattern will be encoded in the tag in any case,
    /// ensuring safety from collision attacks.
    fn from(domain: Domain) -> Self {
        match domain {
            // 2^4 - 1
            Domain::Merkle4 => 0x0000_0000_0000_000f,
            // 2^2 - 1
            Domain::Merkle2 => 0x0000_0000_0000_0003,
            // 2^32
            Domain::Encryption => 0x0000_0001_0000_0000,
            // 0
            Domain::Other => 0x0000_0000_0000_0000,
        }
    }
}

// This function, which is called during the finalization step of the hash,
// builds the io-pattern from the input.
// The function will return an error if a merkle domain is selected but the
// given input elements don't add up to the specified arity.
// The returned io-pattern is not validated: no input, an empty input chunk, or
// an input chunk or output length above 2^31 - 1 yields a pattern that
// `Sponge::start` rejects.
fn io_pattern<T>(
    domain: Domain,
    input: &[&[T]],
    output_len: usize,
) -> Result<Vec<Call>, Error> {
    let mut io_pattern = Vec::new();
    // check total input length against domain
    let input_len = input.iter().fold(0, |acc, input| acc + input.len());
    match domain {
        Domain::Merkle2 if input_len != 2 || output_len != 1 => {
            return Err(Error::IOPatternViolation);
        }
        Domain::Merkle4 if input_len != 4 || output_len != 1 => {
            return Err(Error::IOPatternViolation);
        }
        _ => {}
    }
    for input in input.iter() {
        io_pattern.push(Call::Absorb(input.len()));
    }
    io_pattern.push(Call::Squeeze(output_len));

    Ok(io_pattern)
}

/// Hash any given input into one or several scalar using the Hades
/// permutation strategy. The Hash can absorb multiple chunks of input but will
/// only call `squeeze` once at the finalization of the hash.
/// The output length is set to 1 element per default, but this can be
/// overridden with [`Hash::output_len`].
pub struct Hash<'a> {
    domain: Domain,
    input: Vec<&'a [BlsScalar]>,
    output_len: usize,
}

impl<'a> Hash<'a> {
    /// Create a new hash.
    pub fn new(domain: Domain) -> Self {
        Self {
            domain,
            input: Vec::new(),
            output_len: 1,
        }
    }

    /// Override the length of the hash output (default value is 1) when using
    /// the hash for anything other than hashing a merkle tree or
    /// encryption.
    pub fn output_len(&mut self, output_len: usize) {
        if self.domain == Domain::Other && output_len > 0 {
            self.output_len = output_len;
        }
    }

    /// Update the hash input.
    pub fn update(&mut self, input: &'a [BlsScalar]) {
        self.input.push(input);
    }

    /// Finalize the hash.
    ///
    /// # Panics
    /// This function panics when:
    /// - no input was given, i.e. [`Hash::update`] was never called,
    /// - a chunk passed to [`Hash::update`] is empty,
    /// - a chunk passed to [`Hash::update`] has more than 2^31 - 1 elements,
    /// - the output length set with [`Hash::output_len`] is above 2^31 - 1,
    /// - [`Domain::Merkle2`] or [`Domain::Merkle4`] is used with a total input
    ///   length other than 2 or 4 respectively.
    ///
    /// Use [`Hash::try_finalize`] to get an error instead.
    pub fn finalize(&self) -> Vec<BlsScalar> {
        self.try_finalize()
            .expect("the hash input should match the io-pattern rules")
    }

    /// Finalize the hash and return an error instead of a panic on invalid
    /// input.
    ///
    /// # Errors
    /// This function returns [`Error::IOPatternViolation`] when
    /// [`Domain::Merkle2`] or [`Domain::Merkle4`] is used with a total input
    /// length other than 2 or 4 respectively, including no input at all.
    ///
    /// Otherwise, it returns [`Error::InvalidIOPattern`] when:
    /// - no input was given, i.e. [`Hash::update`] was never called,
    /// - a chunk passed to [`Hash::update`] is empty,
    /// - a chunk passed to [`Hash::update`] has more than 2^31 - 1 elements,
    /// - the output length set with [`Hash::output_len`] is above 2^31 - 1.
    pub fn try_finalize(&self) -> Result<Vec<BlsScalar>, Error> {
        // Generate the hash using the sponge framework:
        // initialize the sponge
        let mut sponge = Sponge::start(
            ScalarPermutation::new(),
            io_pattern(self.domain, &self.input, self.output_len)?,
            self.domain.into(),
        )?;

        // absorb the input
        for input in self.input.iter() {
            sponge.absorb(input.len(), input)?;
        }

        // squeeze output_len elements
        sponge.squeeze(self.output_len)?;

        // return the result
        Ok(sponge.finish()?)
    }

    /// Finalize the hash and output the result as a `JubJubScalar` by
    /// truncating the `BlsScalar` output to 250 bits.
    ///
    /// # Panics
    /// This function panics when:
    /// - no input was given, i.e. [`Hash::update`] was never called,
    /// - a chunk passed to [`Hash::update`] is empty,
    /// - a chunk passed to [`Hash::update`] has more than 2^31 - 1 elements,
    /// - the output length set with [`Hash::output_len`] is above 2^31 - 1,
    /// - [`Domain::Merkle2`] or [`Domain::Merkle4`] is used with a total input
    ///   length other than 2 or 4 respectively.
    ///
    /// Use [`Hash::try_finalize_truncated`] to get an error instead.
    pub fn finalize_truncated(&self) -> Vec<JubJubScalar> {
        self.try_finalize_truncated()
            .expect("the hash input should match the io-pattern rules")
    }

    /// Finalize the hash and output the result as a `JubJubScalar` by
    /// truncating the `BlsScalar` output to 250 bits. Return an error instead
    /// of a panic on invalid input.
    ///
    /// # Errors
    /// This function returns the same errors as [`Hash::try_finalize`].
    pub fn try_finalize_truncated(&self) -> Result<Vec<JubJubScalar>, Error> {
        // bit-mask to 'cast' a bls-scalar result to a jubjub-scalar by
        // truncating the 6 highest bits
        const TRUNCATION_MASK: BlsScalar = BlsScalar::from_raw([
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x03ff_ffff_ffff_ffff,
        ]);

        // finalize the hash as bls-scalar
        let bls_output = self.try_finalize()?;

        Ok(bls_output
            .iter()
            .map(|bls| {
                JubJubScalar::from_raw((bls & &TRUNCATION_MASK).reduce().0)
            })
            .collect())
    }

    /// Digest an input and calculate the hash immediately
    ///
    /// # Panics
    /// This function panics when:
    /// - the input is empty,
    /// - the input has more than 2^31 - 1 elements,
    /// - [`Domain::Merkle2`] or [`Domain::Merkle4`] is used with an input
    ///   length other than 2 or 4 respectively.
    ///
    /// Use [`Hash::try_digest`] to get an error instead.
    pub fn digest(domain: Domain, input: &'a [BlsScalar]) -> Vec<BlsScalar> {
        Self::try_digest(domain, input)
            .expect("the hash input should match the io-pattern rules")
    }

    /// Digest an input and calculate the hash immediately. Return an error
    /// instead of a panic on invalid input.
    ///
    /// # Errors
    /// This function returns [`Error::IOPatternViolation`] when
    /// [`Domain::Merkle2`] or [`Domain::Merkle4`] is used with an input length
    /// other than 2 or 4 respectively, including an empty input.
    ///
    /// Otherwise, it returns [`Error::InvalidIOPattern`] when:
    /// - the input is empty,
    /// - the input has more than 2^31 - 1 elements.
    pub fn try_digest(
        domain: Domain,
        input: &'a [BlsScalar],
    ) -> Result<Vec<BlsScalar>, Error> {
        let mut hash = Self::new(domain);
        hash.update(input);
        hash.try_finalize()
    }

    /// Digest an input and calculate the hash as jubjub-scalar immediately
    ///
    /// # Panics
    /// This function panics when:
    /// - the input is empty,
    /// - the input has more than 2^31 - 1 elements,
    /// - [`Domain::Merkle2`] or [`Domain::Merkle4`] is used with an input
    ///   length other than 2 or 4 respectively.
    ///
    /// Use [`Hash::try_digest_truncated`] to get an error instead.
    pub fn digest_truncated(
        domain: Domain,
        input: &'a [BlsScalar],
    ) -> Vec<JubJubScalar> {
        Self::try_digest_truncated(domain, input)
            .expect("the hash input should match the io-pattern rules")
    }

    /// Digest an input and calculate the hash as jubjub-scalar immediately.
    /// Return an error instead of a panic on invalid input.
    ///
    /// # Errors
    /// This function returns the same errors as [`Hash::try_digest`].
    pub fn try_digest_truncated(
        domain: Domain,
        input: &'a [BlsScalar],
    ) -> Result<Vec<JubJubScalar>, Error> {
        let mut hash = Self::new(domain);
        hash.update(input);
        hash.try_finalize_truncated()
    }
}
