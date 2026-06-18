#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright (c) DUSK NETWORK. All rights reserved.

"""Derive the optimized Poseidon tables from arc.bin and mds.bin."""

import argparse
import re
from pathlib import Path


WIDTH = 5
FULL_ROUNDS = 8
PARTIAL_ROUNDS = 60
MODULUS = int(
    "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
    16,
)


def add(left, right):
    return (left + right) % MODULUS


def mul(left, right):
    return (left * right) % MODULUS


def read_scalars(path):
    data = path.read_bytes()
    if len(data) % 32 != 0:
        raise ValueError(f"{path} length is not a multiple of 32 bytes")

    return [
        int.from_bytes(data[offset : offset + 32], "little")
        for offset in range(0, len(data), 32)
    ]


def chunks(values, size):
    return [values[offset : offset + size] for offset in range(0, len(values), size)]


def identity(size):
    return [[int(row == column) for column in range(size)] for row in range(size)]


def matrix_mul(left, right):
    return [
        [
            sum(
                mul(left[row][index], right[index][column])
                for index in range(len(right))
            )
            % MODULUS
            for column in range(len(right[0]))
        ]
        for row in range(len(left))
    ]


def row_mul(row, matrix):
    return [
        sum(mul(value, matrix[index][column]) for index, value in enumerate(row))
        % MODULUS
        for column in range(len(matrix[0]))
    ]


def matrix_inverse(matrix):
    size = len(matrix)
    augmented = [row[:] + identity(size)[index] for index, row in enumerate(matrix)]

    for column in range(size):
        pivot = next(
            (row for row in range(column, size) if augmented[row][column] != 0),
            None,
        )
        if pivot is None:
            raise ValueError("matrix is singular")

        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        pivot_inverse = pow(augmented[column][column], -1, MODULUS)
        augmented[column] = [mul(value, pivot_inverse) for value in augmented[column]]

        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                (value - mul(factor, pivot_value)) % MODULUS
                for value, pivot_value in zip(augmented[row], augmented[column])
            ]

    return [row[size:] for row in augmented]


def optimized_round_constants(round_constants, mds):
    half_full_rounds = FULL_ROUNDS // 2
    mds_inverse = matrix_inverse(mds)
    optimized = round_constants[0][:]

    for round_index in range(1, half_full_rounds):
        optimized.extend(row_mul(round_constants[round_index], mds_inverse))

    partial_constants = []
    final_partial_round = half_full_rounds + PARTIAL_ROUNDS
    accumulator = round_constants[final_partial_round][:]

    for round_index in range(PARTIAL_ROUNDS):
        accumulator = row_mul(accumulator, mds_inverse)
        partial_constants.append(accumulator[0])
        accumulator[0] = 0
        accumulator = [
            add(value, constant)
            for value, constant in zip(
                accumulator,
                round_constants[final_partial_round - round_index - 1],
            )
        ]

    optimized.extend(row_mul(accumulator, mds_inverse))
    optimized.extend(reversed(partial_constants))

    for round_index in range(1, half_full_rounds):
        optimized.extend(
            row_mul(
                round_constants[final_partial_round + round_index],
                mds_inverse,
            )
        )

    return optimized


def sparse_factorization(matrix):
    size = len(matrix)
    dense = [row[:] for row in matrix]
    dense[0] = [0] * size
    for row in range(size):
        dense[row][0] = 0
    dense[0][0] = 1

    lower_right = [row[1:] for row in matrix[1:]]
    first_column = [[row[0]] for row in matrix[1:]]
    transformed_column = matrix_mul(matrix_inverse(lower_right), first_column)

    sparse = identity(size)
    sparse[0] = matrix[0][:]
    for row in range(1, size):
        sparse[row][0] = transformed_column[row - 1][0]

    if matrix_mul(dense, sparse) != matrix:
        raise ValueError("sparse matrix factorization failed")

    return dense, sparse


def optimized_matrices(mds):
    current = [row[:] for row in mds]
    sparse_matrices = []

    for _ in range(PARTIAL_ROUNDS):
        dense, sparse = sparse_factorization(current)
        sparse_matrices.append(sparse)
        current = matrix_mul(mds, dense)

    sparse_matrices.reverse()
    return current, sparse_matrices


def raw_limbs(value):
    return [(value >> (64 * index)) & (pow(2, 64) - 1) for index in range(4)]


def render_scalar(value, indent):
    limbs = raw_limbs(value)
    lines = [f"{' ' * indent}BlsScalar::from_raw(["]
    lines.extend(f"{' ' * (indent + 4)}0x{limb:016x}," for limb in limbs)
    lines.append(f"{' ' * indent}]),")
    return lines


def render_array(name, values, declaration):
    lines = [f"{declaration} {name} = ["]
    for value in values:
        lines.extend(render_scalar(value, 4))
    lines.append("];")
    return lines


def render_matrix(name, matrix, declaration):
    lines = [f"{declaration} {name} = ["]
    for row in matrix:
        lines.append("    [")
        for value in row:
            lines.extend(render_scalar(value, 8))
        lines.append("    ],")
    lines.append("];")
    return lines


def render_module(constants, pre_sparse, sparse_matrices):
    lines = [
        "// This Source Code Form is subject to the terms of the Mozilla Public",
        "// License, v. 2.0. If a copy of the MPL was not distributed with this",
        "// file, You can obtain one at http://mozilla.org/MPL/2.0/.",
        "//",
        "// Copyright (c) DUSK NETWORK. All rights reserved.",
        "",
        "//! Optimized Poseidon constants derived from `assets/arc.bin` and",
        "//! `assets/mds.bin` by `assets/derive_optimized_constants.py`.",
        "//!",
        "//! These constants encode an algebraically equivalent schedule for the existing",
        "//! Hades252 permutation. They do not define a new hash function.",
        "//!",
        "//! The pre-sparse and sparse matrices use row-vector storage: the permutation",
        "//! computes `result[column] += state[row] * matrix[row][column]`. This is",
        "//! transposed relative to the dense MDS multiplication in `permutation.rs`.",
        "",
        "use dusk_bls12_381::BlsScalar;",
        "",
        "use crate::hades::{PARTIAL_ROUNDS, WIDTH};",
    ]
    lines.extend(
        render_array(
            "OPT_ROUND_CONSTANTS: [BlsScalar; 100]",
            constants,
            "pub(crate) const",
        )
    )
    lines.extend(
        render_matrix(
            "PRE_SPARSE_MATRIX: [[BlsScalar; WIDTH]; WIDTH]",
            pre_sparse,
            "pub(crate) const",
        )
    )

    compressed_sparse = [
        [matrix[row][0] for row in range(WIDTH)] + matrix[0][1:]
        for matrix in sparse_matrices
    ]
    lines.extend(
        render_matrix(
            "SPARSE_MATRICES: [[BlsScalar; 2 * WIDTH - 1]; PARTIAL_ROUNDS]",
            compressed_sparse,
            "pub(crate) static",
        )
    )
    return "\n".join(lines) + "\n"


def derive(repository):
    round_constants = chunks(read_scalars(repository / "assets/arc.bin"), WIDTH)
    mds = chunks(read_scalars(repository / "assets/mds.bin"), WIDTH)

    expected_rounds = FULL_ROUNDS + PARTIAL_ROUNDS
    if len(round_constants) != expected_rounds or len(mds) != WIDTH:
        raise ValueError("asset dimensions do not match the Hades252 parameters")

    # The optimized permutation reverses its state so the partial S-box is at
    # index zero. Apply the same basis change to the source tables first.
    round_constants = [list(reversed(row)) for row in round_constants]
    mds = [list(reversed(row)) for row in reversed(mds)]

    constants = optimized_round_constants(round_constants, mds)
    pre_sparse, sparse_matrices = optimized_matrices(mds)
    return constants, pre_sparse, sparse_matrices


def checked_scalars(source):
    pattern = re.compile(
        r"BlsScalar::from_raw\(\[\s*"
        r"(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*"
        r"(0x[0-9a-f]+),\s*(0x[0-9a-f]+),\s*\]\)",
        re.MULTILINE,
    )
    return [
        sum(int(limb, 16) << (64 * index) for index, limb in enumerate(match))
        for match in pattern.findall(source)
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        help="write the generated Rust module to this path",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify src/hades/optimized_constants.rs without rewriting it",
    )
    args = parser.parse_args()
    if bool(args.output) == args.check:
        parser.error("select exactly one of --output or --check")

    repository = Path(__file__).resolve().parent.parent
    constants, pre_sparse, sparse_matrices = derive(repository)
    rendered = render_module(constants, pre_sparse, sparse_matrices)

    if args.output:
        args.output.write_text(rendered)
        return

    checked_path = repository / "src/hades/optimized_constants.rs"
    generated_values = checked_scalars(rendered)
    checked_values = checked_scalars(checked_path.read_text())
    expected_values = 100 + WIDTH * WIDTH + PARTIAL_ROUNDS * (2 * WIDTH - 1)
    if len(generated_values) != expected_values:
        raise SystemExit("generator emitted an unexpected number of scalars")
    if generated_values != checked_values:
        raise SystemExit(f"{checked_path} does not match the derived constants")

    print(f"{checked_path} matches arc.bin and mds.bin")


if __name__ == "__main__":
    main()
