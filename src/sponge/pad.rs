//! Padding support for sponge hash
//!

pub(crate) fn pad<T>(messages: &[T], width: usize, pad_value: T, eom_value: T) -> Vec<T>
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
    use dusk_bls12_381::Scalar;
    use dusk_plonk::constraint_system::StandardComposer;

    #[test]
    fn test_scalar_padding_width_3() {
        let pad_value = Scalar::zero();
        let eom_value = Scalar::one();
        let two = Scalar::from(2u64);
        let three = Scalar::from(3u64);
        let four = Scalar::from(4u64);

        assert_eq!(
            &pad(&[two], 3, pad_value, eom_value),
            &[pad_value, two, eom_value]
        );
        assert_eq!(
            &pad(&[two, three], 3, pad_value, eom_value),
            &[pad_value, two, three, pad_value, eom_value, pad_value]
        );
        assert_eq!(
            &pad(&[two, three, four], 3, pad_value, eom_value),
            &[pad_value, two, three, pad_value, four, eom_value]
        );
    }

    #[test]
    fn test_scalar_padding_width_4() {
        let pad_value = Scalar::zero();
        let eom_value = Scalar::one();
        let two = Scalar::from(2u64);
        let three = Scalar::from(3u64);
        let four = Scalar::from(4u64);

        assert_eq!(
            &pad(&[two], 4, pad_value, eom_value),
            &[pad_value, two, eom_value, pad_value]
        );
        assert_eq!(
            &pad(&[two, three], 4, pad_value, eom_value),
            &[pad_value, two, three, eom_value]
        );
        assert_eq!(
            &pad(&[two, three, four], 4, pad_value, eom_value),
            &[pad_value, two, three, four, pad_value, eom_value, pad_value, pad_value]
        );
    }

    #[test]
    fn test_variable_padding() {
        let mut composer = StandardComposer::new();
        let pad_value = composer.add_input(Scalar::zero());
        let eom_value = composer.add_input(Scalar::one());
        let two = composer.add_input(Scalar::from(2u64));
        let three = composer.add_input(Scalar::from(3u64));
        let four = composer.add_input(Scalar::from(4u64));

        assert_eq!(
            &pad(&[two], 3, pad_value, eom_value),
            &[pad_value, two, eom_value]
        );
        assert_eq!(
            &pad(&[two, three], 3, pad_value, eom_value),
            &[pad_value, two, three, pad_value, eom_value, pad_value]
        );
        assert_eq!(
            &pad(&[two, three, four], 3, pad_value, eom_value),
            &[pad_value, two, three, pad_value, four, eom_value]
        );
    }
}
