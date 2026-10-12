# cosmos-mpc

Cosmos Hub with a 2-of-2 DKLs23 key:

1. distributed key generation;
2. the `cosmos1...` address (bech32 of `RIPEMD160(SHA256(compressed key))`);
3. a bank `MsgSend` of 1 ATOM wrapped in a sign document
   (`pkg/chain/cosmos`), hashed with SHA-256;
4. a threshold signature over the hash, printed in the base64 `r || s` form
   Cosmos uses;
5. local verification against the group public key.

Limitation: `pkg/chain/cosmos` encodes the sign document as JSON. A
broadcastable `SIGN_MODE_DIRECT` transaction requires the protobuf encoding of
`TxBody`, `AuthInfo` and `SignDoc`, so this example demonstrates the key,
address and signature format but does not produce a transaction a node would
accept. Account number and sequence are placeholders.

## Run

```sh
make build-ffi        # once: builds the Rust FFI libraries
go run ./examples/cosmos-mpc
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first.

## Sample output

```
Cosmos Hub: DKLs23 2-of-2, bank MsgSend
=======================================

1. Distributed key generation
   public key           0281e80156fdbbe3b498791ba695b641d71f3e65e553c508699571d7d384d78b51

2. Address
   Cosmos address       cosmos1snvfxv5fs3zgtj0kyuwh6l5wy40jdwn9k09lyg

3. Sign document
   message              MsgSend 1 ATOM to cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c
   chain / account      cosmoshub-4 / account 12345, sequence 1
   sha256(sign bytes)   f62eb987f084cf403f9fcc5e8289fa64fe36f837ea909c7091be771f5029fdee

4. Threshold signing
   signature (base64)   RWbg5gEBlwT/8aTJL98Qi8g2A238R19JgCP0S/GaftEkFfZIVgGk1wgI/y/f2AZbW516cOZF5Q5iDahtYnlheA==

5. Verification
   secp256k1 ECDSA      valid

OK: sign document signed and verified
```
