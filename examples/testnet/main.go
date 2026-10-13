// Command testnet signs a transaction with a 2-of-3 threshold key against a
// real public test network, so that acceptance by real nodes can be checked
// end to end: real UTXOs / nonces / block hashes are fetched from a public
// API, the transaction is built with pkg/chain, signed by two of the three
// parties, verified locally and, only with -broadcast, submitted.
//
// Usage:
//
//	go run ./examples/testnet <bitcoin|ethereum|solana|tron|near> [flags]
//
// The first run creates TEST ONLY keyshares in a local file and prints the
// address to fund from a faucet. Every network is checked (genesis hash or
// chain ID) and mainnet is refused. Without -broadcast nothing is sent.
package main

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
)

// options holds the flags shared by every chain.
type options struct {
	keyshares    string
	to           string
	amount       string
	rpc          string
	btcNet       string
	feeRate      float64
	broadcast    bool
	assumeFunded bool
}

type chainRunner struct {
	scheme string // "dkls23" or "frost"
	title  string
	run    func(keyshares []string, o options) error
}

var chains = map[string]chainRunner{
	"bitcoin":  {schemeDKLS23, "Bitcoin testnet4/signet: DKLs23 2-of-3, P2WPKH spend", runBitcoin},
	"ethereum": {schemeDKLS23, "Ethereum Sepolia: DKLs23 2-of-3, EIP-155 transfer", runEthereum},
	"tron":     {schemeDKLS23, "Tron Nile/Shasta: DKLs23 2-of-3, TRX transfer", runTron},
	"solana":   {schemeFROST, "Solana devnet: FROST 2-of-3, SOL transfer", runSolana},
	"near":     {schemeFROST, "NEAR testnet: FROST 2-of-3, NEAR transfer", runNEAR},
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: go run ./examples/testnet <chain> [flags]

chains: bitcoin, ethereum, solana, tron, near

TEST NETWORKS ONLY. Keyshares are stored unencrypted in a local file.
Without -broadcast the signed transaction is printed and nothing is sent.

flags:
`)
	newFlagSet(&options{}).PrintDefaults()
}

func newFlagSet(o *options) *flag.FlagSet {
	fs := flag.NewFlagSet("testnet", flag.ExitOnError)
	fs.Usage = usage
	fs.StringVar(&o.keyshares, "keyshares", "", "keyshare file, created on first run (default .testnet-keys/<dkls23|frost>.keyshare.json)")
	fs.StringVar(&o.to, "to", "", "recipient address (default: the threshold address itself; required for tron)")
	fs.StringVar(&o.amount, "amount", "", "amount in base units: sats, wei, lamports, sun, yoctoNEAR (default: a tiny per-chain amount)")
	fs.StringVar(&o.rpc, "rpc", "", "API / JSON-RPC endpoint override (default: a public test network endpoint)")
	fs.StringVar(&o.btcNet, "btc-net", "testnet4", "bitcoin network: testnet4 or signet")
	fs.Float64Var(&o.feeRate, "fee-rate", 0, "bitcoin fee rate in sat/vB (default: API estimate, at least 1)")
	fs.BoolVar(&o.broadcast, "broadcast", false, "submit the signed transaction to the network")
	fs.BoolVar(&o.assumeFunded, "assume-funded", false, "if the address is unfunded, use a made-up balance/UTXO to exercise the pipeline (cannot be combined with -broadcast)")
	return fs
}

func main() {
	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
		usage()
		os.Exit(2)
	}
	name := strings.ToLower(os.Args[1])
	c, ok := chains[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown chain %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	var o options
	_ = newFlagSet(&o).Parse(os.Args[2:]) // ExitOnError
	if o.keyshares == "" {
		o.keyshares = filepath.Join(".testnet-keys", c.scheme+".keyshare.json")
	}

	mpcdemo.Run(c.title, func() error {
		if o.broadcast && o.assumeFunded {
			return errors.New("-assume-funded builds a transaction that cannot be valid; it cannot be combined with -broadcast")
		}
		fmt.Println("\nTEST NETWORKS ONLY: keyshares are kept unencrypted on disk; never use them for real funds.")
		keyshares, err := loadOrCreateKeyshares(o.keyshares, c.scheme)
		if err != nil {
			return err
		}
		return c.run(keyshares, o)
	})
}

// amountOr parses -amount as a non-negative integer, or returns def.
func amountOr(s string, def *big.Int) (*big.Int, error) {
	if s == "" {
		return def, nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() <= 0 {
		return nil, fmt.Errorf("-amount %q: want a positive integer in base units", s)
	}
	return v, nil
}

// amountUint64 is amountOr for chains whose amounts fit in uint64.
func amountUint64(s string, def uint64) (uint64, error) {
	v, err := amountOr(s, new(big.Int).SetUint64(def))
	if err != nil {
		return 0, err
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("-amount %s is too large", s)
	}
	return v.Uint64(), nil
}

// finish prints the signed transaction and either stops (dry run) or calls
// submit and prints the explorer link.
func finish(o options, rawLabel, raw string, submit func() (string, error), explorer func(id string) string) error {
	mpcdemo.Field(rawLabel, raw)
	if !o.broadcast {
		mpcdemo.Done("dry run: transaction signed and verified locally, NOT broadcast (pass -broadcast to submit)")
		return nil
	}
	mpcdemo.Step(8, "Broadcast")
	id, err := submit()
	if err != nil {
		return fmt.Errorf("broadcast: %w", err)
	}
	mpcdemo.Field("txid", id)
	mpcdemo.Field("explorer", explorer(id))
	mpcdemo.Done("transaction accepted by the node")
	return nil
}

// faucetHint prints funding instructions. It returns nil: an unfunded address
// is the expected state after the first run, not a failure.
func faucetHint(address string, lines ...string) error {
	fmt.Println()
	fmt.Println("   The address has no usable funds yet. Fund it from a faucet, then run again:")
	mpcdemo.Field("address", address)
	for _, l := range lines {
		fmt.Println("   - " + l)
	}
	fmt.Println("   (or pass -assume-funded to dry-run the signing pipeline with a made-up balance)")
	fmt.Println("\nNothing was signed or sent.")
	return nil
}
