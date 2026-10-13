package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/blocto/solana-go-sdk/common"
	"github.com/mr-tron/base58"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/solana"
)

const solDefaultRPC = "https://api.devnet.solana.com"

// solClusters is an allowlist keyed by genesis hash; mainnet-beta
// (5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d) is refused.
var solClusters = map[string]string{
	"EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG": "devnet",
	"4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY": "testnet",
}

const (
	solDefaultAmount = 1_000 // lamports
	solFeePerSig     = 5_000 // lamports, base fee for one signature
)

func runSolana(keyshares []string, o options) error {
	url := o.rpc
	if url == "" {
		url = solDefaultRPC
	}

	pub, err := mpcdemo.FROSTPublicKey(keyshares[0])
	if err != nil {
		return err
	}
	from, err := solana.DeriveAddress(pub)
	if err != nil {
		return err
	}
	mpcdemo.Step(2, "Threshold address")
	mpcdemo.Field("address", from.ToBase58())

	mpcdemo.Step(3, "Network check")
	var genesis string
	if err := jsonRPC(url, "getGenesisHash", []any{}, &genesis); err != nil {
		return err
	}
	cluster, ok := solClusters[genesis]
	if !ok {
		return fmt.Errorf("%s has genesis %s, which is not devnet or testnet (mainnet-beta is refused)", url, genesis)
	}
	mpcdemo.Field("RPC", url)
	mpcdemo.Field("cluster", cluster)

	to := from
	if o.to != "" {
		b, err := base58.Decode(o.to)
		if err != nil || len(b) != 32 {
			return fmt.Errorf("-to %q is not a Solana address", o.to)
		}
		to = common.PublicKeyFromBytes(b)
	}
	amount, err := amountUint64(o.amount, solDefaultAmount)
	if err != nil {
		return err
	}

	mpcdemo.Step(4, "Chain data")
	balance, err := solBalance(url, from)
	if err != nil {
		return err
	}
	mpcdemo.Field("balance", fmt.Sprintf("%d lamports", balance))
	if to != from {
		toBalance, err := solBalance(url, to)
		if err != nil {
			return err
		}
		var rentMin uint64
		if err := jsonRPC(url, "getMinimumBalanceForRentExemption", []any{0}, &rentMin); err != nil {
			return err
		}
		if toBalance+amount < rentMin {
			return fmt.Errorf("recipient would hold %d lamports, below the rent-exempt minimum %d; send at least %d",
				toBalance+amount, rentMin, rentMin-toBalance)
		}
	}
	if balance < amount+solFeePerSig {
		if !o.assumeFunded {
			return faucetHint(from.ToBase58(),
				"https://faucet.solana.com (choose devnet; 0.5-5 SOL)",
				"or with the Solana CLI: solana airdrop 1 "+from.ToBase58()+" --url devnet",
				"funds are usable within a few seconds")
		}
		mpcdemo.Field("ASSUMED BALANCE", "address is unfunded (-assume-funded); the cluster would reject this transaction")
	}
	var bh struct {
		Value struct {
			Blockhash            string `json:"blockhash"`
			LastValidBlockHeight uint64 `json:"lastValidBlockHeight"`
		} `json:"value"`
	}
	if err := jsonRPC(url, "getLatestBlockhash", []any{map[string]string{"commitment": "finalized"}}, &bh); err != nil {
		return err
	}
	mpcdemo.Field("recent blockhash", bh.Value.Blockhash)

	mpcdemo.Step(5, "Unsigned transaction")
	msg, err := solana.BuildTransferSOL(from, to, amount, bh.Value.Blockhash)
	if err != nil {
		return err
	}
	raw, err := msg.Serialize()
	if err != nil {
		return err
	}
	mpcdemo.Field("to", fmt.Sprintf("%s (%d lamports)", to.ToBase58(), amount))
	mpcdemo.Field("message", fmt.Sprintf("%d bytes", len(raw)))

	mpcdemo.Step(6, "Threshold signing (parties 1 and 3)")
	sig, err := mpcdemo.FROSTSign(signers(keyshares), raw)
	if err != nil {
		return err
	}
	mpcdemo.Field("signature", hex.EncodeToString(sig))

	mpcdemo.Step(7, "Local verification and signed transaction")
	if err := mpcdemo.VerifyEd25519(pub, raw, sig); err != nil {
		return err
	}
	mpcdemo.Field("crypto/ed25519", "valid")
	tx, err := solana.AssembleTransaction(msg, sig, from)
	if err != nil {
		return err
	}
	wire, err := tx.Serialize()
	if err != nil {
		return err
	}
	b64 := base64.StdEncoding.EncodeToString(wire)
	mpcdemo.Field("tx signature (id)", base58.Encode(sig))

	// simulateTransaction is read-only: the node checks the signature and
	// executes the transaction without committing it.
	var sim struct {
		Value struct {
			Err  json.RawMessage `json:"err"`
			Logs []string        `json:"logs"`
		} `json:"value"`
	}
	simCfg := map[string]any{"encoding": "base64", "sigVerify": true, "commitment": "confirmed"}
	if err := jsonRPC(url, "simulateTransaction", []any{b64, simCfg}, &sim); err != nil {
		return fmt.Errorf("simulate: %w", err)
	}
	// The node verifies signatures before loading accounts, so even for an
	// unfunded address AccountNotFound (rather than SignatureFailure) shows
	// that a real validator accepted the threshold signature.
	switch simErr := string(sim.Value.Err); {
	case simErr == "" || simErr == "null":
		mpcdemo.Field("node simulation", "OK (signature verified and transfer executed by the node)")
	case simErr == `"AccountNotFound"` && o.assumeFunded:
		mpcdemo.Field("node simulation", "signature accepted by the node; fee payer not funded (AccountNotFound)")
	default:
		mpcdemo.Field("node simulation", "FAILED: "+simErr)
		return fmt.Errorf("node simulation failed: %s", simErr)
	}

	explorer := func(id string) string { return "https://explorer.solana.com/tx/" + id + "?cluster=" + cluster }
	return finish(o, "base64 tx", b64, func() (string, error) {
		var id string
		cfg := map[string]any{"encoding": "base64", "preflightCommitment": "confirmed"}
		err := jsonRPC(url, "sendTransaction", []any{b64, cfg}, &id)
		return id, err
	}, explorer)
}

func solBalance(url string, a common.PublicKey) (uint64, error) {
	var res struct {
		Value uint64 `json:"value"`
	}
	err := jsonRPC(url, "getBalance", []any{a.ToBase58(), map[string]string{"commitment": "confirmed"}}, &res)
	return res.Value, err
}
