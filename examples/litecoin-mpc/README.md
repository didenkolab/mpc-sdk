# litecoin-mpc

Litecoin with a 2-of-2 DKLs23 key:

1. distributed key generation;
2. mainnet P2PKH (`L...`) and P2WPKH (`ltc1q...`) addresses;
3. legacy and SegWit (BIP143) self-spends of one UTXO with their sighashes
   (`pkg/chain/litecoin`);
4. a threshold signature per sighash, encoded as strict low-S DER and attached
   as scriptSig / witness;
5. validation of both signed transactions with the script engine (Litecoin
   uses Bitcoin's script rules).

The input UTXO is a placeholder, so the transactions are not broadcastable.

## Run

```sh
make build-ffi        # once: builds the Rust FFI libraries
go run ./examples/litecoin-mpc
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first.

## Sample output

```
Litecoin: DKLs23 2-of-2, P2PKH and P2WPKH
=========================================

1. Distributed key generation
   public key           0284ebd56840ebeaa938030472c2b8bd530718c24d3d4a653e0f3451e249c360d8

2. Addresses
   P2PKH                LeB92te2L6fbUMqnDCrBWnjyQtzQPRpshN
   P2WPKH               ltc1qel3zrukplf8md9frxy9jnepvu3uvrv55dqacyz

3. Unsigned transactions (self-spend)
   input                79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798:0 (100000000 litoshi)
   payment              50000000 litoshi
   fee                  1000 litoshi
   P2PKH sighash        c07862fd07797f2dd18f833ad9b9d5fd66bae7d8d304892d099fd76d0410fceb
   P2WPKH sighash       4492934a820195166cf55f7aaf44e8673395b9cd515789e309a0facee02e778e

4. Threshold signing
   P2PKH signature      30450221009a85a6d350da10b5...
   P2WPKH signature     304402205d81aeda02ab0d5df8...

5. Script validation
   P2PKH                valid
   P2WPKH               valid

6. Signed transactions
   P2PKH txid           bf5c20923ef315325cd15ce8bd07f66b2d18c134795bd073f2fcde722bef458b
   P2PKH raw            01000000019817f8165b81f259...
   P2WPKH txid          481a43814aa271331efdc8d6f7c056db44bcaeab6fdf21d5ed28ffffd657485c
   P2WPKH raw           010000000001019817f8165b81...

OK: both transactions pass script validation
```
