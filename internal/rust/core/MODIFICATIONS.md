# Modifications to silent-shard-dkls23-ll

This crate is derived from
[silence-laboratories/silent-shard-dkls23-ll](https://github.com/silence-laboratories/silent-shard-dkls23-ll)
(`src/`, crate version 1.0.3) and remains under the Silence Laboratories License
Agreement (see `LICENSE.md` and the repository `NOTICE`).

Modifications by Vadym Didenko, November 2025 – October 2026:

| File | Change |
|------|--------|
| `src/dkg.rs` | Added `KeygenMode` (Standard / Hierarchical) and `Party::new_with_ranks` for ranked (hierarchical) key generation; added `Keyshare::apply_secret_offset` for child-key derivation; `Zeroize` on keyshare and DKG state with manual zeroization in `Drop`. |
| `src/dsg.rs` | Implemented ranked signing via Birkhoff interpolation (`get_birkhoff_coefficients`), falling back to Lagrange coefficients for zero ranks; added tests for ranked signing. |
| `src/dsg_ot_variant.rs` | Replaced the `unimplemented!()` ranked branch with Birkhoff coefficients; set `compatibility_breaking_field` to `1` so peers can detect this protocol variant. |
| `src/lib.rs` | Removed the optional `vrf` module. |

`constants.rs`, `error.rs`, `pairs.rs` and `utils.rs` are unmodified.

