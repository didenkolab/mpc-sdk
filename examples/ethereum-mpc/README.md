# ethereum-mpc

Ethereum and other EVM chains with a 2-of-2 DKLs23 key:

1. distributed key generation;
2. the EVM address of the group key, which is the same on every EVM chain;
3. EIP-155 legacy transactions (`pkg/chain/evm`): an ETH transfer and a USDC
   (ERC-20) transfer on Ethereum mainnet, and a native transfer on BSC,
   Polygon, Arbitrum and Avalanche C-Chain;
4. a threshold signature per transaction hash, converted to Ethereum's
   65-byte `r || s || v` form (recovery ID found by trial, low S);
5. verification by recovering the sender with go-ethereum's `types.Sender`
   and comparing it to the MPC address.

Nonces and gas prices are fixed demo values, so the transactions are not meant
to be broadcast as-is.

## Run

```sh
make build-ffi        # once: builds the Rust FFI libraries
go run ./examples/ethereum-mpc
```

On Linux, export `LD_LIBRARY_PATH=$PWD/internal/rust/target/release` first.

## Sample output

```
Ethereum and EVM chains: DKLs23 2-of-2, EIP-155 transactions
============================================================

1. Distributed key generation
   public key           02fef4a4966f3bd1ed70a7b95557338c2a0fa506b5545ca5225efb3d2f409691ad

2. Address
   EVM address          0x8fc3cfE8E63BAE44DA312D752dC3bb8bEBa42d87

3. Ethereum mainnet: ETH and ERC-20 transfers
   ETH transfer hash    0xc130aefb236e3b63bfb78e12fc532fd8aa8a4b0e7e021ab5bbd37a63a87180b2
   ETH transfer raw     0xf86c808504a817c800825208...
   USDC transfer hash   0x14b5fff19e944bb5d624f9aff2efbdc4ab7c3ab290e51f0cebb688ccb53c09a3
   USDC transfer raw    0xf8a9018504a817c80082ea60...

4. Same key on other EVM chains
   BSC (56)             0xf5d1347ebf7f3681f0f21dbdead3bc63477915d31bf754e0cf41f003510613a5
   Polygon (137)        0xca83dfa5aab5cfd96383eff254080bc0aeac8f299b07ae1b31777577e19993a1
   Arbitrum (42161)     0x1fccee4051e64d25608e05d7b15e34e07e102de9ca4b801c4bfff272049f88a3
   Avalanche (43114)    0x8dfdcf3b105173210e7c907db78daa99fc4fff2d7944af9df2399451c6b6b3a0

OK: every transaction recovers to the MPC address
```
