# testnet

End-to-end check against **real public test networks**: a 2-of-3 threshold key
signs a transaction built from live chain data, and a real node accepts it.

The other examples use placeholder UTXOs, nonces and block hashes, so they only
prove that signatures verify locally. This one fetches real inputs, builds the
transaction with `pkg/chain`, signs it with parties 1 and 3 (party 2 never
participates), verifies it locally and, only with `-broadcast`, submits it.

| Chain | Network (default) | Protocol | Public endpoint (default) |
|-------|-------------------|----------|---------------------------|
| `bitcoin` | testnet4 (`-btc-net signet` also works) | DKLs23 | mempool.space Esplora API |
| `ethereum` | Sepolia (Hoodi also allowed) | DKLs23 | `ethereum-sepolia-rpc.publicnode.com` |
| `solana` | devnet (testnet also allowed) | FROST | `api.devnet.solana.com` |
| `tron` | Nile (Shasta also allowed) | DKLs23 | `nile.trongrid.io` |
| `near` | testnet | FROST | `rpc.testnet.fastnear.com` |

## Safety

- **Test networks only.** Before doing anything, each run checks the network
  through the API: Bitcoin, Solana and Tron by genesis hash, Ethereum by chain
  ID, NEAR by `chain_id`. Mainnet, or any network not on the allowlist, is
  refused, even when you pass it with `-rpc`.
- **Keyshares are TEST ONLY.** On first run an in-process DKG creates the
  keyshares of all three parties and writes them unencrypted to one file
  (mode 0600, directory 0700). That gives up the point of MPC, so never put
  real funds on these addresses. The default location
  `.testnet-keys/{dkls23,frost}.keyshare.json` (relative to the working
  directory) is in `.gitignore`. Do not commit it.
- **Dry run by default.** Without `-broadcast` the signed transaction is
  printed and nothing is sent. Default amounts are tiny, and the default
  recipient is the threshold address itself (Tron needs `-to`, because it
  rejects transfers to yourself).

Bitcoin, Ethereum and Tron share the DKLs23 key file. Solana and NEAR share the
FROST file (on NEAR the implicit account ID is the hex of the Solana public
key).

## Steps

Run every command from the repository root. Build the FFI libraries once with
`make build-ffi`. On Linux, also
`export LD_LIBRARY_PATH=$PWD/internal/rust/target/release`.

**1. Create the key and get the address**

```sh
go run ./examples/testnet solana
```

```
1. Distributed key generation (frost 2-of-3, new key)
   saved to             .testnet-keys/frost.keyshare.json (mode 0600, TEST ONLY, do not commit)
2. Threshold address
   address              4FKtadM3UXYCTZNgjakkGjS9TmDbMFJo3vCMqCuscrtB
3. Network check
   cluster              devnet
4. Chain data
   balance              0 lamports

   The address has no usable funds yet. Fund it from a faucet, then run again:
   - https://faucet.solana.com (choose devnet; 0.5-5 SOL)
   ...
Nothing was signed or sent.
```

**2. Fund the address from a faucet**

| Chain | Faucet | Wait before step 3 |
|-------|--------|--------------------|
| bitcoin testnet4 | https://faucet.testnet4.dev, https://mempool.space/testnet4/faucet, https://coinfaucet.eu/en/btc-testnet4/ | 1 confirmation, about 10 min (the tool spends confirmed UTXOs only) |
| bitcoin signet | https://signetfaucet.com, https://alt.signetfaucet.com | 1 confirmation, about 10 min |
| ethereum Sepolia | https://sepolia-faucet.pk910.de (PoW, no account needed), Google Cloud or Alchemy Sepolia faucets | about 12 s |
| solana devnet | https://faucet.solana.com, or `solana airdrop 1 <addr> --url devnet` | a few seconds |
| tron Nile | https://nileex.io/join/getJoinPage | about 3 s |
| near testnet | https://near-faucet.io, or send from a testnet account (`near tokens <you>.testnet send-near <implicit-id> '1 NEAR' ...`) | about 1 s |

Some faucets require a login, a small mainnet balance or a captcha. The
pk910 PoW faucet and the Solana CLI airdrop usually work without either.

**3. Dry run with live chain data**

```sh
go run ./examples/testnet solana            # sends 1000 lamports back to itself
```

The output shows the real chain data (balance, blockhash, nonce or UTXO, fee),
the unsigned transaction, the threshold signature, local verification and the
raw signed transaction. On Solana the node also checks the transaction with a
read-only `simulateTransaction` call, including signature verification.

**4. Broadcast**

```sh
go run ./examples/testnet solana -broadcast
```

```
8. Broadcast
   txid                 3vZ...
   explorer             https://explorer.solana.com/tx/3vZ...?cluster=devnet
OK: transaction accepted by the node
```

Open the explorer link. The transaction is final when the explorer shows it
confirmed: Bitcoin about 10 min, Ethereum about 12 s, the others a few seconds.

More examples:

```sh
go run ./examples/testnet bitcoin -broadcast                         # 10000 sats to itself (testnet4)
go run ./examples/testnet bitcoin -btc-net signet -to tb1q... -amount 5000
go run ./examples/testnet ethereum -broadcast                        # 0.00001 ETH to itself
SEPOLIA_RPC_URL=https://... go run ./examples/testnet ethereum        # your own RPC endpoint
go run ./examples/testnet tron -to T... -broadcast                   # 1 TRX
go run ./examples/testnet near -broadcast                            # 0.001 NEAR to itself
```

## Flags

| Flag | Meaning |
|------|---------|
| `-keyshares path` | keyshare file, created on first run |
| `-to addr` | recipient (default: self; required for Tron; Bitcoin: P2WPKH `tb1q...` only) |
| `-amount n` | base units: sats, wei, lamports, sun or yoctoNEAR |
| `-rpc url` | endpoint override (Esplora base URL, JSON-RPC URL or TronGrid base URL); Ethereum also reads `SEPOLIA_RPC_URL` |
| `-btc-net` | `testnet4` (default) or `signet` |
| `-fee-rate` | Bitcoin sat/vB (default: API estimate, at least 1; fee is capped at 50000 sats) |
| `-broadcast` | submit the signed transaction |
| `-assume-funded` | for an unfunded address, use a made-up balance or UTXO to exercise the pipeline. The result is not valid, and the flag cannot be combined with `-broadcast` |

## Limitations

These come from `pkg/chain` as it is today:

- **Bitcoin.** `BuildP2WPKH` spends one input, so the largest confirmed UTXO
  must cover amount plus fee. It pays only to P2WPKH outputs and takes a fixed
  fee (sized here for 141 vB).
- **Ethereum.** Transactions are legacy EIP-155 (`gasPrice`, no EIP-1559
  fields). Nodes still accept them. Only plain 21000-gas transfers to
  non-contract addresses are sent.
- **Tron.** Before signing, a funded run asks the node to build the same
  transfer with `createtransaction`. This call is read-only and broadcasts
  nothing. The run stops if the `raw_data` bytes from `pkg/chain/tron` differ
  from the node's. As of this writing they do differ: `pkg/chain/tron` encodes
  `timestamp` as protobuf field 13, but Tron defines it as field 14. Expect
  this check to fail until the bug is fixed.
