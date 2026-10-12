# bitcoin-mpc

Bitcoin with a 2-of-2 DKLs23 key:

1. distributed key generation;
2. mainnet P2PKH (`1...`) and P2WPKH (`bc1q...`) addresses from the group key;
3. legacy and SegWit spends of one UTXO (payment plus change) with their
   sighashes (`pkg/chain/bitcoin`);
4. a threshold signature per sighash, encoded as strict low-S DER and attached
   as scriptSig / witness;
5. validation of both signed transactions with the btcd script engine, the
   same checks a node runs.

The default input is a placeholder UTXO, so the transactions are valid against
it but not broadcastable. To spend a real output, pass an output owned by the
printed address; the destination defaults to the MPC key itself.

## Run

```sh
make build-ffi        # once: builds the Rust FFI libraries
go run ./examples/bitcoin-mpc
go run ./examples/bitcoin-mpc -utxo-txid <txid> -utxo-vout 0 -utxo-amount 150000 -amount 100000 -fee 500
```

Flags: `-utxo-txid`, `-utxo-vout`, `-utxo-amount`, `-amount`, `-fee` (all in
satoshis) and `-to` (P2PKH or P2WPKH destination). On Linux, export
`LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first.

## Sample output

```
Bitcoin: DKLs23 2-of-2, P2PKH and P2WPKH
========================================

1. Distributed key generation
   public key           02e6d8c1dd603cd97673ef6ea46bb71f578629cc040bef598a1d57a0df86bbb251

2. Addresses
   P2PKH                1PzBPBKBh1EVZ3bhUPCRejYrhTMUPrXjPN
   P2WPKH               bc1qls3jf5n50w63acte53sfv5axednlwaur62hcek

3. Unsigned transactions
   input                79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798:0 (1 BTC)
   payment              0.50000000 BTC
   fee                  0.00001000 BTC
   P2PKH sighash        189e2a6c32cfd087eaa01f7a22162e2efe9f9003949cbfa2b41281aefee6d31d
   P2WPKH sighash       82b4cd3f89feb4233ea23a8edd9a31331f5ab7ec6e66ec702bb70e1dcdd922e2

4. Threshold signing
   P2PKH signature      3045022100d7cf4977a04ae140...
   P2WPKH signature     30450221009f4a7f285e674257...

5. Script validation
   P2PKH                valid
   P2WPKH               valid

6. Signed transactions
   P2PKH txid           39903634645a682a146cf0e622f21825f6ad1af7248f16328acd706b0da60be9
   P2PKH raw            01000000019817f8165b81f259...
   P2WPKH txid          082912d9db2553ee476795bf871410b2766c655897ab30bd10d6e5b61e0bed5c
   P2WPKH raw           010000000001019817f8165b81...

OK: both transactions pass Bitcoin script validation
```
