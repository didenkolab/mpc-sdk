# Ranked (hierarchical) participants

DKLs23 keys can be created in two modes:

| Mode | Constructor | Signing coefficients |
|------|-------------|----------------------|
| Standard | `dkls23.NewDKGState(partyID, n, t)` | Lagrange |
| Hierarchical | `dkls23.NewDKGStateWithRanks(partyID, ranks, t)` | Birkhoff |

FROST keys support the standard mode only; `frost.NewDKGStateWithRanks`
accepts all-zero ranks for API symmetry and rejects anything else.

## How ranks work

The DKG shares a secret polynomial `f` of degree `t-1`. A party with rank 0
receives `f(x_i)`, as in standard mode. A party with rank `r > 0` receives the
`r`-th derivative `f^(r)(x_i)` instead. Ranks therefore change the shares
produced by key generation, not only the signing step: the protocol messages
are the same, but each party evaluates the polynomial (or its derivative)
according to its rank, and the ranks are stored in every keyshare as
`rank_list`.

When signing, each party weights its share with Birkhoff coefficients computed
from the signers' `x_i` and ranks. A set of signers can sign only if their
shares determine `f(0)`, which means lower ranks are more privileged. With
three parties, `t = 2` and ranks `[0 1 1]`:

- `{0,1}` and `{0,2}` can sign;
- `{1,2}` cannot: two first-derivative values say nothing about `f(0)`.

This models setups such as a user device (rank 0) plus two co-signing servers
that must never be able to sign without it.

If all ranks are 0, the key is a standard key and signing uses Lagrange
coefficients.

## Rules

- `len(ranks)` is the number of parties; `ranks[i]` is the rank of party `i`.
- `max(ranks) < t <= len(ranks)`, enforced by `NewDKGStateWithRanks` and by
  the FFI.
- Signing uses exactly `t` parties. The combined signature is verified against
  the group public key before it is returned.
- Choose ranks so that the signing sets you need are valid. Signing with an
  invalid set (for example `{1,2}` above) is not detected up front and can
  abort the process inside the native library, so validate signing sets in
  the application.

## Go API

```go
// Standard 2-of-3: every rank is 0.
p0, err := dkls23.NewDKGState(0, 3, 2)

// Hierarchical 2-of-3: party 0 has rank 0, parties 1 and 2 have rank 1.
p0, err := dkls23.NewDKGStateWithRanks(0, []uint8{0, 1, 1}, 2)
```

The rest of the DKG and the whole signing flow are identical in both modes.
[examples/ranked-participants-example](../examples/ranked-participants-example)
runs both modes end to end and verifies every signature.

## Rust core

The ranked mode lives in the vendored DKLs23 crate (`internal/rust/core`,
package `dkls23-ll`); see `internal/rust/core/MODIFICATIONS.md`:

- `dkg::Party::new(n, t, party_id)` (standard), `Party::new_with_ranks(ranks,
  t, party_id)` and `Party::new_with_mode(ranks, t, party_id, mode)` with
  `KeygenMode::{Standard, Hierarchical}`;
- `dsg::get_birkhoff_coefficients` for ranked signing.

```sh
cd internal/rust
cargo test -p dkls23-ll                                     # all core tests
cargo test -p dkls23-ll test_birkhoff_coefficients_function # Birkhoff coefficients
```

## Limitations

- Ranked mode is supported for DKLs23 (ECDSA secp256k1) only.
- The ranked (Birkhoff) signing path is a modification of the upstream crate
  and has not been reviewed by a third party (see [SECURITY.md](../SECURITY.md)).
