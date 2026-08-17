# Poseidon Gadget Constraints

The Hades252 gadget preserves the native Poseidon permutation exactly. The
optimization is limited to circuit representation; it does not change the
field, width, alpha, round counts, constants, MDS matrices, SAFE domains, output
encoding, or test vectors.

The previous gadget eagerly materialized the result of each sparse MDS layer in
every partial round. Since ARK and MDS are linear operations, the optimized
gadget keeps partial-round state coordinates as linear expressions for two
rounds at a time and materializes the full state only at that boundary. This
keeps expression growth bounded while avoiding some unnecessary linear gates.

The first full-round constants are also folded into the first S-box inputs. This
removes the initial constant-addition gates without changing the permutation:

```text
(x + c)^5 + d
```

is constrained directly with the same three multiplication gates used for
`x^5 + d`.

With `dusk-plonk` 0.22 arithmetic gates, the raw width-5 permutation now costs:

```text
S-boxes:                 100 * 3 = 300
full/pre-sparse layers:   8 * 10 = 80
partial sparse layers:             270
raw permutation total:             650
```

The previous sparse-MDS gadget cost was approximately:

```text
S-boxes:                 100 * 3 = 300
full/pre-sparse layers:   8 * 10 = 80
partial sparse layers:    60 * 6 = 360
initial constants:                   5
raw permutation total:             745
```

These counts are measurement notes, not consensus parameters. The semantic tests
continue to compare gadget outputs against the native implementation and reject
incorrect public hash outputs.
