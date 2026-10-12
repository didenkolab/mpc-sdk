# tron-mpc

Tron with a 2-of-2 DKLs23 key:

1. distributed key generation;
2. the Tron address (`T...`, base58check of `0x41 || keccak256(pubkey)[12:]`);
3. a 1 TRX transfer serialized as protobuf `raw_data` (`pkg/chain/tron`);
   the transaction ID is `sha256(raw_data)`;
4. a threshold signature over the transaction ID in the 65-byte recoverable
   form Tron expects;
5. verification by recovering the public key from the signature and
   re-deriving the Tron address.

The reference block (`ref_block_bytes` / `ref_block_hash`) is a placeholder;
a broadcastable transaction needs values from a recent block.

## Run

```sh
make build-ffi        # once: builds the Rust FFI libraries
go run ./examples/tron-mpc
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first.

## Sample output

```
Tron: DKLs23 2-of-2, TRX transfer
=================================

1. Distributed key generation
   public key           032d4d0f4eb119d15064bd83a8102dbc0dc07a436ae8db2ac58411f154ec8edace

2. Address
   Tron address         TJWcXNj8rt9qRQEYU4YMGpxZazn9KXxynt

3. Unsigned TRX transfer
   to                   TLBaRhANQoJFTqre9Nf1mjuwNWjCJeYqUL
   amount               1 TRX
   txID                 21528d781215eab040d9c3ad32bc6badc9b279aace854a203c323241c6e26398

4. Threshold signing
   signature            5e53a29150654045a77e24fe...

5. Verification
   recovered signer     TJWcXNj8rt9qRQEYU4YMGpxZazn9KXxynt

6. Signed transaction
   raw_data_hex         0a020d3a22088fa9e75800000000...
   JSON                 {"raw_data":{"contract":[{"type":"TransferContract",...

OK: signature recovers to the MPC Tron address
```
