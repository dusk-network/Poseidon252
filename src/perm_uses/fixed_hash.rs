// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.”
//! The `pad` module implements the Sponge's padding algorithm
use crate::sponge::pad::*;

use dusk_plonk::prelude::*;
use hades252::strategies::*;
use hades252::WIDTH;


/// Takes in one BlsScalar and outputs 2. 
/// This function is fixed.
pub fn two_outputs(message: BlsScalar) -> [BlsScalar; 2] {
    let mut strategy = ScalarStrategy::new();

    // The value used to pad the words is zero.
    let padder = BlsScalar::zero();

    // The capacity is 
    let capacity = BlsScalar::one() * BlsScalar::from(2<<64-1) + BlsScalar::one(); 

    let mut words = pad_fixed_hash(capacity, message, padder);
    // If the words len is less than the Hades252 permutation `WIDTH` we directly
    // call the permutation saving useless additions by zero.
    if words.len() == WIDTH {
        strategy.perm(&mut words);
        return [words[1], words[2]];
    }
    // If the words len is bigger than the Hades252 permutation `WIDTH` then we
    // need to collapse the padded limbs. See bottom of pag. 16 of
    // https://eprint.iacr.org/2019/458.pdf
    words.chunks(WIDTH).fold(
        vec![BlsScalar::zero(); WIDTH],
        |mut inputs, values| {
            let mut values = values.iter();
            inputs
                .iter_mut()
                .for_each(|input| *input += values.next().unwrap());
            strategy.perm(&mut inputs);
            inputs
        },
    );
    [words[1], words[2]]
} 

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn hash_two_outputs() {
        let m = BlsScalar::random(&mut rand::thread_rng()); 
        
        let h = two_outputs(m); 
        
        assert_eq!(h.len(), 2);
        assert_ne!(m, BlsScalar::zero());
        assert_ne!(h[0], BlsScalar::zero());
        assert_ne!(h[1], BlsScalar::zero());
    }

    #[test]
    fn same_result() {
        let m = BlsScalar::random(&mut rand::thread_rng()); 
        
        let h = two_outputs(m); 
        let h_1 = two_outputs(m);
        
        assert_eq!(h, h_1);
    }
}