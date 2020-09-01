// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! Padding support for sponge hash
//!

pub(crate) fn pad<T>(
    messages: &[T],
    width: usize,
    pad_value: T,
    eom_value: T,
) -> Vec<T>
where
    T: Clone,
{
    let length = messages.len() + 1;
    let arity = width - 1;
    let offset = ((length % arity) != 0) as usize;
    let size = (length / arity + offset) * width;

    let zero = pad_value;
    let one = eom_value;
    let mut words = vec![zero; size];
    let mut messages = messages.iter();

    for chunk in words.chunks_mut(width) {
        for elem in chunk.iter_mut().skip(1) {
            if let Some(message) = messages.next() {
                *elem = message.clone();
            } else {
                *elem = one;
                return words;
            }
        }
    }
    words
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use dusk_plonk::prelude::*;

    #[test]
    fn test_scalar_padding_width_3() {
        let padder = BlsScalar::zero();
        let eom = BlsScalar::one();
        let two = BlsScalar::from(2u64);
        let three = BlsScalar::from(3u64);
        let four = BlsScalar::from(4u64);

        assert_eq!(&pad(&[two], 3, padder, eom), &[padder, two, eom]);
        assert_eq!(
            &pad(&[two, three], 3, padder, eom),
            &[padder, two, three, padder, eom, padder]
        );
        assert_eq!(
            &pad(&[two, three, four], 3, padder, eom),
            &[padder, two, three, padder, four, eom]
        );
    }

    #[test]
    fn test_scalar_padding_width_4() {
        let padder = BlsScalar::zero();
        let eom = BlsScalar::one();
        let two = BlsScalar::from(2u64);
        let three = BlsScalar::from(3u64);
        let four = BlsScalar::from(4u64);

        assert_eq!(&pad(&[two], 4, padder, eom), &[padder, two, eom, padder]);
        assert_eq!(
            &pad(&[two, three], 4, padder, eom),
            &[padder, two, three, eom]
        );
        assert_eq!(
            &pad(&[two, three, four], 4, padder, eom),
            &[padder, two, three, four, padder, eom, padder, padder]
        );
    }

    #[test]
    fn test_variable_padding() {
        let mut composer = StandardComposer::new();
        let padder = composer.add_input(BlsScalar::zero());
        let eom = composer.add_input(BlsScalar::one());
        let two = composer.add_input(BlsScalar::from(2u64));
        let three = composer.add_input(BlsScalar::from(3u64));
        let four = composer.add_input(BlsScalar::from(4u64));

        assert_eq!(&pad(&[two], 3, padder, eom), &[padder, two, eom]);
        assert_eq!(
            &pad(&[two, three], 3, padder, eom),
            &[padder, two, three, padder, eom, padder]
        );
        assert_eq!(
            &pad(&[two, three, four], 3, padder, eom),
            &[padder, two, three, padder, four, eom]
        );
    }
}
