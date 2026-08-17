<!-- This Source Code Form is subject to the terms of the Mozilla Public -->
<!-- License, v. 2.0. If a copy of the MPL was not distributed with this -->
<!-- file, You can obtain one at http://mozilla.org/MPL/2.0/. -->

<!-- Copyright (c) DUSK NETWORK. All rights reserved. -->

# How to generate the assets

The `arc.bin` and `mds.bin` files in this folder are generated using the snippets below:

## Generate round constants

```rust
use dusk_bls12_381::BlsScalar;
use sha2::{Digest, Sha512};
use std::fs;
use std::io::Write;

// The amount of constants generated, this needs to be at least the total number
// of rounds (= 60 + 8) multiplied by the width of the permutation array (= 5).
const CONSTANTS: usize = (60 + 8) * 5;

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
    let filename = "arc.bin";
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

## Generate mds matrix

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

## Derive the optimized schedule

The checked-in `OPT_ROUND_CONSTANTS`, `PRE_SPARSE_MATRIX`, and
`SPARSE_MATRICES` tables in `src/hades/optimized_constants.rs` are derived from
`arc.bin` and `mds.bin` by `derive_optimized_constants.py`. The script uses only
the Python standard library and implements the optimized Poseidon derivation
described in the [Neptune specification].

The derivation first reverses the source constants and both axes of the MDS
matrix. This is a basis change that moves the legacy schedule's partial S-box
from the last state element to the first. It then performs the following two
transformations over the BLS12-381 scalar field:

- It folds round constants through inverse MDS layers. Full-round vectors are
  multiplied by the inverse MDS matrix. Across the partial-round block, the
  constants are accumulated backwards through the inverse layers; the first
  coordinate is retained for the next partial S-box and the remaining
  coordinates are folded into the preceding round. This produces 100 optimized
  constants instead of the original 340.
- It repeatedly factors the current dense matrix as `M' * M''`, where `M'` has
  first row and column zero except for `M'[0][0] = 1`, and `M''` contains only
  its first row, first column, and an identity lower-right block. The next
  factorization starts from `MDS * M'`. After 60 factorizations, the final dense
  factor is the pre-sparse matrix and the `M''` factors, in reverse order, are
  the per-round sparse matrices.

The pre-sparse and sparse tables are stored for right multiplication of a row
vector: `result[column] += state[row] * matrix[row][column]`. Their access is
therefore transposed relative to the dense MDS multiplication in the Rust
permutation. The generator emits the tables in this storage orientation.

From the repository root, verify that the checked-in Rust tables match the
binary source assets exactly:

```console
python3 assets/derive_optimized_constants.py --check
```

To regenerate the Rust module and format it:

```console
python3 assets/derive_optimized_constants.py \
    --output src/hades/optimized_constants.rs
make fmt
python3 assets/derive_optimized_constants.py --check
```

[Neptune specification]: https://spec.filecoin.io/algorithms/crypto/poseidon/
