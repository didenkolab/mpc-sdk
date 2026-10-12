# basic-dkls23

A complete DKLs23 session written out round by round, with no helpers hiding
the message flow: a 2-of-2 distributed key generation (four rounds), a
distributed signature (three rounds, presignature, partial signatures,
combine), and local verification of the ECDSA signature against the group
public key. Both parties run in one process; in a real deployment they run on
separate devices and exchange the same messages over a network.

The chain examples reuse this flow through `examples/internal/mpcdemo`.

## Run

```sh
make build-ffi                        # once: builds the Rust FFI libraries
go run ./examples/basic-dkls23        # standard mode (Lagrange coefficients)
go run ./examples/basic-dkls23 -ranked  # hierarchical mode, ranks [0 1] (Birkhoff)
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first so
the shared FFI libraries are found at run time.

## Sample output

```
DKLs23 threshold ECDSA: 2-of-2 key generation and signing
=========================================================

1. Distributed key generation (2-of-2)
   mode                 standard, all ranks 0 (Lagrange coefficients)
   round 1 (broadcast)  344 / 351 bytes
   round 2 (p2p)        60318 / 60229 bytes
   round 3 (p2p)        133472 / 133341 bytes
   round 4 (broadcast)  328 / 328 bytes
   group public key     028a60e2366a02bca627c3202ffb69eb1cf400f9a362b433321b1f8c18b1455823
   keyshare sizes       232022 / 232036 bytes

2. Distributed signing
   message              "DKLs23 threshold signature example"
   sha256               2a6eef7af618e374f056c9e663248090cb2818021503ed3f038122557ef4d0f9
   rounds 1-3           commitments, MtA, consistency proofs exchanged
   signature (r||s)     38a51ee3b5e351bf...

3. Local verification
   secp256k1 ECDSA      valid

OK: signature created without either party holding the full private key
```

Keys are fresh on every run, so keys and signatures differ each time.
