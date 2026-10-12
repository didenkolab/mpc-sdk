# solana-frost-mpc

Solana with a 2-of-3 FROST (Ed25519) key:

1. distributed key generation between three parties (threshold 2);
2. the Solana address (base58 of the 32-byte group public key);
3. a 0.1 SOL System Program transfer message (`pkg/chain/solana`);
4. a threshold signature by parties 2 and 3 over the serialized message, as
   Solana requires (`solana.SignMessageWithFROST`);
5. verification with Go's `crypto/ed25519`, then the signed transaction in
   the base64 wire format accepted by `sendTransaction`.

The recent blockhash is a placeholder; a broadcastable transaction needs a
current blockhash from an RPC node.

## Run

```sh
make build-ffi        # once: builds the Rust FFI libraries
go run ./examples/solana-frost-mpc
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first.

## Sample output

```
Solana: FROST 2-of-3, SOL transfer
==================================

1. Distributed key generation (2-of-3)
   public key (hex)     1dd783a02a490b44978d746cf732eb55441c523e1033df31bba63eb7dfd8c7fe

2. Address
   Solana address       31VResxNe8vDj3Gc5KW1bhoeJ3rUhvieHJZzRXQ2byuP

3. Transfer message
   transfer             0.1 SOL to 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM
   message              150 bytes

4. Threshold signing (parties 2 and 3)
   signature            be8eafbfcd326bc1ce2255a8...

5. Verification
   Ed25519              valid

6. Signed transaction
   base64 (for RPC)     Ab6Or7/NMmvBziJVqN7z6qDS...

OK: signature by 2 of 3 parties verifies against the group key
```
