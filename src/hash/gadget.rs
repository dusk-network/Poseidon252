// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::vec::Vec;

use dusk_plonk::prelude::{Composer, Witness};
use dusk_safe::Sponge;

use crate::hades::GadgetPermutation;
use crate::{Domain, Error};

use super::io_pattern;

/// Hash struct.
pub struct HashGadget<'a> {
    domain: Domain,
    input: Vec<&'a [Witness]>,
    output_len: usize,
}

impl<'a> HashGadget<'a> {
    /// Create a new hash.
    pub fn new(domain: Domain) -> Self {
        Self {
            domain,
            input: Vec::new(),
            output_len: 1,
        }
    }

    /// Override the length of the hash output (default value is 1).
    pub fn output_len(&mut self, output_len: usize) {
        self.output_len = output_len;
    }

    /// Update the hash input.
    pub fn update(&mut self, input: &'a [Witness]) {
        self.input.push(input);
    }

    /// Finalize the hash.
    pub fn finalize(
        &self,
        composer: &mut Composer,
    ) -> Result<Vec<Witness>, Error> {
        // Generate the hash using the sponge framework:
        // initialize the sponge
        let mut sponge = Sponge::start(
            GadgetPermutation::new(composer),
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

    /// Finalize the hash and output JubJubScalar.
    pub fn finalize_truncated(
        &self,
        composer: &mut Composer,
    ) -> Result<Vec<Witness>, Error> {
        // finalize the hash as bls-scalar witnesses
        let bls_output = self.finalize(composer)?;

        // truncate the bls witnesses to 250 bits
        Ok(bls_output
            .iter()
            .map(|bls| composer.append_logic_xor::<125>(*bls, Composer::ZERO))
            .collect())
    }

    /// Digest an input and calculate the hash immediately
    pub fn digest(
        domain: Domain,
        composer: &mut Composer,
        input: &'a [Witness],
    ) -> Result<Vec<Witness>, Error> {
        let mut hash = Self::new(domain);
        hash.update(input);
        hash.finalize(composer)
    }

    /// Digest an input and calculate the hash as jubjub-scalar immediately
    pub fn digest_truncated(
        domain: Domain,
        composer: &mut Composer,
        input: &'a [Witness],
    ) -> Result<Vec<Witness>, Error> {
        let mut hash = Self::new(domain);
        hash.update(input);
        hash.finalize_truncated(composer)
    }
}
