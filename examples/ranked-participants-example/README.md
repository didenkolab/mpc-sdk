# ranked-participants-example

Compares standard and hierarchical (ranked) DKLs23 keys with three parties and
threshold 2.

- **Standard mode** (`dkls23.NewDKGState`): every rank is 0, every party holds
  an evaluation of the secret polynomial, and any two parties can sign
  (Lagrange interpolation).
- **Hierarchical mode** (`dkls23.NewDKGStateWithRanks`): ranks `[0 1 1]`.
  Party 0 holds a polynomial evaluation, parties 1 and 2 hold first-derivative
  evaluations. A signing set must be able to reconstruct the secret (Birkhoff
  interpolation), so every valid set includes party 0. This models, for
  example, a user device (rank 0) and two co-signing servers that cannot sign
  on their own.

For each mode the example runs DKG, prints the `rank_list` recorded in the
keyshares, signs with every valid pair and verifies each signature locally.
See [docs/ranked-participants.md](../../docs/ranked-participants.md) for the
rules on ranks and thresholds.

## Run

```sh
make build-ffi        # once: builds the Rust FFI libraries
go run ./examples/ranked-participants-example
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first.

## Sample output

```
DKLs23 ranked participants: standard vs hierarchical 2-of-3
===========================================================

1. Standard mode, ranks [0 0 0]
   public key           021eaf38f390cd88b28b31edd037764b1986188480d8f79fae9ebf2182dfbcf50b
   keyshare rank_list   [0 0 0]
   parties {0,1}        signature valid
   parties {1,2}        signature valid
   parties {0,2}        signature valid

2. Hierarchical mode, ranks [0 1 1]
   public key           03d5c906f3b87c790bbfcfa4e73616704408c8ae0779ac5936cba17da6c3c8c23f
   keyshare rank_list   [0 1 1]
   parties {0,1}        signature valid
   parties {0,2}        signature valid
   parties {1,2}        not a valid signing set (no rank-0 share)

OK: every valid signing set produced a verified signature
```
