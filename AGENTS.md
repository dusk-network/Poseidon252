# AGENTS.md — dusk-poseidon

## Care Level: Cryptographic — Elevated

Core hash function used across the Dusk stack (nullifiers, Merkle trees,
encryption). A bug here affects consensus and privacy.

## Overview

Poseidon hash over the BLS12-381 scalar field. Uses the Hades252
permutation (8 full + 60 partial rounds, width 5) via the SAFE sponge
framework. Single crate, `no_std` with `alloc`.

## Commands

Run `make help` for the full target list.

## Architecture

### Key Files

| Path | Purpose |
|------|---------|
| `src/hash.rs` | `Hash` struct — sponge-based with domain separation (Merkle2/4, Encryption, Other) |
| `src/hades.rs` | Hades252 permutation algorithm |
| `src/hades/mds_matrix.rs` | MDS (Cauchy) matrix constants |
| `src/hades/round_constants.rs` | 340 round constants |
| `src/encryption.rs` | Encrypt/decrypt using Poseidon + JubJub DHKE + SAFE |
| `src/hash/gadget.rs` | ZK circuit gadget for hashing (`zk` feature) |
| `src/encryption/gadget.rs` | ZK gadgets for encryption/decryption (`zk` + `encryption` features) |

### Features

- `zk` — PLONK circuit gadgets (gates `dusk-plonk`)
- `encryption` — encrypt/decrypt module (gates `dusk-safe/encryption`)

## Elevated Care Zones

The entire crate is a care zone — it is a consensus-critical hash
function. Changes to the permutation constants, round structure, or
sponge logic can silently break nullifier derivation, Merkle proofs,
and on-chain encryption.

- **Hades permutation** (`src/hades/`): round constants, MDS matrix,
  and round structure must match the specification exactly.
- **Domain separation** (`src/hash.rs`): changing domain tags breaks
  compatibility with all downstream consumers.
- **Encryption** (`src/encryption.rs`): used for on-chain note
  encryption in Phoenix.

## Conventions

- `no_std` with `alloc` — do not add `std` dependencies
- **Always use `--release` for tests** — the `zk` feature pulls in
  `dusk-plonk`, which is extremely slow in debug mode
- No `unwrap()`/`expect()` outside of tests — return errors instead
- No `#[allow(...)]` lint suppression — fix the underlying issue
- Run `make fmt` before committing (requires nightly toolchain)
- Run `make clippy` to check for warnings

## Change Propagation

| Changed | Also verify |
|---------|-------------|
| `dusk-poseidon` | `merkle` (poseidon-merkle), `phoenix`, `rusk` |

## Git Conventions

- Default branch: `master`
- License: MPL-2.0

### Commit messages

Format: `<Description>` — imperative mood, capitalize first word.

Cross-cutting prefixes (`ci`, `docs`, `chore`) for non-code changes.

## Changelog

Add an entry to `CHANGELOG.md` under `[Unreleased]` only for a change
that users of the crate can see. Tests, CI, tooling and internal
refactors get no entry.

- Write one fact per entry, in one sentence. Two facts get two
  entries.
- Name what changed at the crate's surface: the public item and its
  new behavior. Do not describe how the code does it.
- Name the released item that a breaking change breaks.
- Keep the reason, the consequences and the migration steps in the
  linked issue, not in the entry.
- Choose the section by the effect on users: new things go under
  `Added`, changed behavior goes under `Changed`, and removed things go
  under `Removed`. Use `Fixed` only for a bug that a release had. For a
  bug in unreleased code, correct the entry that added that code.
- Link the tracking GitHub issue, not the PR, and no other tracking
  identifier. Use the link format that the file already uses. A
  reference link needs its definition in the block at the bottom.
- Add to the existing section headings, and leave the other entries as
  they are.
- Use the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
  format.
- Follow standard markdown formatting: separate headings from
  surrounding content with blank lines, leave a blank line before and
  after lists, and never have two headings back-to-back without a blank
  line between them.
