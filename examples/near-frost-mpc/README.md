# near-frost-mpc

NEAR with a 2-of-3 FROST (Ed25519) key:

1. distributed key generation between three parties (threshold 2);
2. the implicit account ID (hex of the 32-byte group public key);
3. a Borsh-encoded transfer of 1 NEAR (`pkg/chain/near`); NEAR signs
   `sha256(serialized transaction)`;
4. a threshold signature by parties 1 and 3;
5. verification with Go's `crypto/ed25519`, then the signed transaction in
   the base64 form accepted by the `broadcast_tx_commit` RPC.

The block hash and nonce are placeholders; a broadcastable transaction needs a
recent block hash and the access key's next nonce from an RPC node.

## Run

```sh
make build-ffi        # once: builds the Rust FFI libraries
go run ./examples/near-frost-mpc
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first.

## Sample output

```
NEAR: FROST 2-of-3, transfer
============================

1. Distributed key generation (2-of-3)
   public key           ed25519:8tUXF8xLcorHvbdhzjAivZm5tj44SCUfYbuzMHnfDcef

2. Account
   implicit account     75318c603629ed5ea9cd841ff3422f881d6a88f8d02a1420f76f3d44ff6022d4

3. Unsigned transfer
   transfer             1 NEAR to receiver.testnet
   sha256(tx)           4e29858528400d88c289212db90ac6d0ed52a164bdbb7f48923551f27aab1d0d

4. Threshold signing (parties 1 and 3)
   signature            4023e74027711d52ef15a8d9...

5. Verification
   Ed25519              valid

6. Signed transaction
   base64 (for RPC)     QAAAADc1MzE4YzYwMzYyOWVk...

OK: signature by 2 of 3 parties verifies against the group key
```
