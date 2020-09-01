// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! Padding support for Poseidon hash
//!

// Padding function for a singular scalar input 
// to provide two outputs from a Poseidon hash
pub fn pad_fixed_hash <T>(
    capacity: T,
    message: T,
    pad_value: T,
) -> Vec<T>
where
    T: Clone,
{
    // For a constant length hash, we always use a slice of width 5.
    let width = 5;
    let zero = pad_value;
    let mut words = vec![zero; width];

    words[0] = capacity;
    words[1] = message;
    words
}
