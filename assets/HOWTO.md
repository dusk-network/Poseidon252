<!-- This Source Code Form is subject to the terms of the Mozilla Public -->
<!-- License, v. 2.0. If a copy of the MPL was not distributed with this -->
<!-- file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

<!-- Copyright (c) DUSK NETWORK. All rights reserved. -->

# How to generate the assets

The `ark.bin` and `mds.bin` files in this folder are generated using the snippets below:

## Filename: ark.bin

```rust
use dusk_bls12_381::BlsScalar;
use sha2::{Digest, Sha512};
use std::fs;
use std::io::Write;

// The amount of constants generated, this needs to be the same number as in
// `dusk_poseidon::hades::CONSTANTS`.
const CONSTANTS: usize = 960;

fn constants() -> [BlsScalar; CONSTANTS] {
    let mut cnst = [BlsScalar::zero(); CONSTANTS];
    let mut p = BlsScalar::one();
    let mut bytes = b"poseidon-for-plonk".to_vec();

    cnst.iter_mut().for_each(|c| {
        let mut hasher = Sha512::new();
        hasher.update(bytes.as_slice());
        bytes = hasher.finalize().to_vec();

        let mut v = [0x00u8; 64];
        v.copy_from_slice(&bytes[0..64]);

        *c = BlsScalar::from_bytes_wide(&v) + p;
        p = *c;
    });

    cnst
}

fn write_constants() -> std::io::Result<()> {
    let filename = "ark.bin";
    let mut buf: Vec<u8> = vec![];

    constants().iter().for_each(|c| {
        c.internal_repr()
            .iter()
            .for_each(|r| buf.extend_from_slice(&(*r).to_le_bytes()));
    });

    let mut file = fs::File::create(filename)?;
    file.write_all(&buf)?;
    Ok(())
}
```

## Filename: mds.bin

```rust
use dusk_bls12_381::BlsScalar;
use std::fs;
use std::io::Write;

// The width of the permutation container, this needs to be the same number as
// in `dusk_poseidon::hades::WIDTH`.
const WIDTH: usize = 5;

fn mds() -> [[BlsScalar; WIDTH]; WIDTH] {
    let mut matrix = [[BlsScalar::zero(); WIDTH]; WIDTH];
    let mut xs = [BlsScalar::zero(); WIDTH];
    let mut ys = [BlsScalar::zero(); WIDTH];

    // Generate x and y values deterministically for the cauchy matrix, where
    // `x[i] != y[i]` to allow the values to be inverted and there are no
    // duplicates in the x vector or y vector, so that the determinant is always
    // non-zero.
    // [a b]
    // [c d]
    // det(M) = (ad - bc) ; if a == b and c == d => det(M) = 0
    // For an MDS matrix, every possible mxm submatrix, must have det(M) != 0
    (0..WIDTH).for_each(|i| {
        xs[i] = BlsScalar::from(i as u64);
        ys[i] = BlsScalar::from((i + WIDTH) as u64);
    });

    let mut m = 0;
    (0..WIDTH).for_each(|i| {
        (0..WIDTH).for_each(|j| {
            matrix[m][j] = (xs[i] + ys[j]).invert().unwrap();
        });
        m += 1;
    });

    matrix
}

fn write_mds() -> std::io::Result<()> {
    let filename = "mds.bin";
    let mut buf: Vec<u8> = vec![];

    mds().iter().for_each(|row| {
        row.iter().for_each(|c| {
            c.internal_repr()
                .iter()
                .for_each(|r| buf.extend_from_slice(&(*r).to_le_bytes()));
        });
    });

    let mut file = fs::File::create(filename)?;
    file.write_all(&buf)?;
    Ok(())
}
```
