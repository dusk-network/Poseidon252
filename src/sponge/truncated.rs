// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Sponge hash and gadget definition

use crate::sponge;
use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubScalar;

#[cfg(feature = "zk")]
use dusk_plonk::prelude::*;

/// The constant represents the bitmask used to truncate the hashing results of
/// a sponge application so that they fit inside of a
/// [`dusk_jubjub::JubJubScalar`] and it's equal to `2^250 - 1`.
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

/// Applies [`hash`] to the `messages` received truncating the result to
/// make it fit inside a `JubJubScalar.`
///
/// [`hash`]: crate::sponge::hash
pub fn hash(messages: &[BlsScalar]) -> JubJubScalar {
    JubJubScalar::from_raw(
        (sponge::hash(messages) & TRUNCATION_LIMIT).reduce().0,
    )
}

/// Mirror the implementation of [`hash`] inside of a PLONK circuit.
///
/// The circuit will be defined by the length of `messages`. This means that a
/// pre-computed circuit will not behave generically for different messages
/// sizes.
///
/// The expected usage is the length of the message to be known publicly as the
/// circuit definition. Hence, the padding value `1` will be appended as a
/// circuit description.
///
/// The returned value is the hashed witness data computed as a variable and
/// truncated to fit inside of a [`JubJubScalar`].
///
/// [`hash`]: crate::sponge::hash
#[cfg(feature = "zk")]
pub fn gadget(composer: &mut Composer, message: &[Witness]) -> Witness {
    let h = sponge::gadget(composer, message);

    // Truncate to 250 bits
    composer.append_logic_xor::<125>(h, Composer::ZERO)
}
