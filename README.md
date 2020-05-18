[![Build Status](https://travis-ci.com/dusk-network/Poseidon252.svg?branch=master)](https://travis-ci.com/dusk-network/Poseidon252)
[![Repository](https://dusk-network.github.io/Poseidon252/repo-badge.svg)](https://github.com/dusk-network/Poseidon252)
[![Documentation](https://dusk-network.github.io/Poseidon252/badge.svg)](https://dusk-network.github.io/Poseidon252/index.html)

# Poseidon252 Sponge Function

Reference implementation for the Poseidon Sponge function.

## Example

```
    use curve25519_dalek::scalar::Scalar;
    use poseidon252::sponge;

    let d = Scalar::zero();
    let m = Scalar::one();

    let x = sponge::hash(&[d, m]);

    println!("{:x?}", x);
```

## Reference

[Starkad and Poseidon: New Hash Functions for Zero Knowledge Proof Systems](https://eprint.iacr.org/2019/458.pdf)

```

```
