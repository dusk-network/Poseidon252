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
