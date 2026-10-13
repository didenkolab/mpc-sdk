package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/bitcoin"
)

type btcNetwork struct {
	api      string // Esplora API base
	explorer string
	genesis  string // block 0 hash, checked before anything else
	faucets  []string
}

var btcNetworks = map[string]btcNetwork{
	"testnet4": {
		api:      "https://mempool.space/testnet4/api",
		explorer: "https://mempool.space/testnet4",
		genesis:  "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
		faucets:  []string{"https://faucet.testnet4.dev", "https://mempool.space/testnet4/faucet", "https://coinfaucet.eu/en/btc-testnet4/"},
	},
	"signet": {
		api:      "https://mempool.space/signet/api",
		explorer: "https://mempool.space/signet",
		genesis:  "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
		faucets:  []string{"https://signetfaucet.com", "https://alt.signetfaucet.com"},
	},
}

const btcMainnetGenesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

const (
	btcDefaultAmount = 10_000 // sats
	btcDust          = 294    // P2WPKH dust limit at the default relay fee
	btcTxVBytes      = 141    // 1 P2WPKH input, 2 P2WPKH outputs
	btcMaxFee        = 50_000 // refuse anything above this (sats)
)

// btcParams encodes addresses. testnet3, testnet4 and signet all use the
// "tb" bech32 prefix, so TestNet3Params produces the right P2WPKH addresses
// for each of them (btcd v0.24 has no testnet4 parameters).
var btcParams = &chaincfg.TestNet3Params

type esploraUTXO struct {
	TxID   string `json:"txid"`
	Vout   uint32 `json:"vout"`
	Value  int64  `json:"value"`
	Status struct {
		Confirmed bool `json:"confirmed"`
	} `json:"status"`
}

func runBitcoin(keyshares []string, o options) error {
	network, ok := btcNetworks[o.btcNet]
	if !ok {
		return fmt.Errorf("-btc-net %q: want testnet4 or signet", o.btcNet)
	}
	api := network.api
	if o.rpc != "" {
		api = strings.TrimRight(o.rpc, "/")
	}

	pub, err := mpcdemo.DKLS23PublicKey(keyshares[0])
	if err != nil {
		return err
	}
	pkHash, err := bitcoin.Hash160Compressed(pub)
	if err != nil {
		return err
	}
	addr, err := bitcoin.DeriveP2WPKHAddress(pub, btcParams)
	if err != nil {
		return err
	}
	mpcdemo.Step(2, "Threshold address")
	mpcdemo.Field("public key", hex.EncodeToString(pub))
	mpcdemo.Field("P2WPKH address", addr.EncodeAddress())

	mpcdemo.Step(3, "Network check")
	genesis, err := getText(api + "/block-height/0")
	if err != nil {
		return err
	}
	switch genesis {
	case btcMainnetGenesis:
		return fmt.Errorf("%s is a Bitcoin MAINNET API; refusing to continue", api)
	case network.genesis:
	default:
		return fmt.Errorf("%s: genesis %s is not %s", api, genesis, o.btcNet)
	}
	mpcdemo.Field("API", api)
	mpcdemo.Field("network", o.btcNet+" (genesis "+genesis[:16]+"...)")

	dest := pkHash
	destAddr := addr.EncodeAddress()
	if o.to != "" {
		if dest, err = btcDestination(o.to); err != nil {
			return fmt.Errorf("-to: %w", err)
		}
		destAddr = o.to
	}
	amount, err := amountUint64(o.amount, btcDefaultAmount)
	if err != nil {
		return err
	}
	if amount < btcDust {
		return fmt.Errorf("amount %d sats is below the %d sat dust limit", amount, btcDust)
	}
	if amount > btcutil.MaxSatoshi {
		return fmt.Errorf("amount %d sats is too large", amount)
	}

	mpcdemo.Step(4, "Chain data")
	var utxos []esploraUTXO
	if err := getJSON(api+"/address/"+addr.EncodeAddress()+"/utxo", &utxos); err != nil {
		return err
	}
	var confirmed []esploraUTXO
	for _, u := range utxos {
		if u.Status.Confirmed {
			confirmed = append(confirmed, u)
		}
	}
	mpcdemo.Field("UTXOs", fmt.Sprintf("%d (%d confirmed)", len(utxos), len(confirmed)))
	if len(confirmed) == 0 {
		if !o.assumeFunded {
			if len(utxos) > 0 {
				fmt.Println("\n   Funds arrived but are unconfirmed. Wait for one block (~10 min) and run again.")
				return nil
			}
			return faucetHint(addr.EncodeAddress(), append(network.faucets,
				"after the faucet pays out, wait for 1 confirmation (~10 minutes)")...)
		}
		fake := sha256.Sum256([]byte("assume-funded"))
		confirmed = []esploraUTXO{{TxID: hex.EncodeToString(fake[:]), Vout: 0, Value: 100_000}}
		mpcdemo.Field("ASSUMED UTXO", "made-up 100000 sat input (-assume-funded); the result is not broadcastable")
	}
	// pkg/chain/bitcoin builds single-input transactions: spend the largest UTXO.
	sort.Slice(confirmed, func(i, j int) bool { return confirmed[i].Value > confirmed[j].Value })
	in := confirmed[0]
	mpcdemo.Field("input", fmt.Sprintf("%s:%d (%s)", in.TxID, in.Vout, btcutil.Amount(in.Value)))

	rate := o.feeRate
	if rate == 0 {
		var est map[string]float64
		if err := getJSON(api+"/fee-estimates", &est); err != nil {
			return err
		}
		rate = est["6"]
	}
	rate = math.Max(rate, 1)
	fee := int64(math.Ceil(rate * btcTxVBytes))
	if fee > btcMaxFee {
		return fmt.Errorf("fee %d sats exceeds the %d sat safety cap; pass a lower -fee-rate", fee, btcMaxFee)
	}
	pay := int64(amount)
	if pay+fee > in.Value {
		return fmt.Errorf("largest UTXO %d sats cannot cover %d + %d fee (single-input spends only)", in.Value, pay, fee)
	}
	if change := in.Value - pay - fee; change > 0 && change < btcDust {
		fee += change // a dust change output would be rejected; give it to the miner
	}
	mpcdemo.Field("fee", fmt.Sprintf("%d sats (%.2f sat/vB x %d vB)", fee, rate, btcTxVBytes))

	mpcdemo.Step(5, "Unsigned transaction")
	utxo := bitcoin.UTXO{TxID: in.TxID, Vout: in.Vout, Amount: in.Value, PkHash: pkHash}
	tx, sighash, err := bitcoin.BuildP2WPKH(utxo, bitcoin.Payment{ToPkHash: dest, Amount: pay, ChangePk: pkHash, Fee: fee}, btcParams)
	if err != nil {
		return err
	}
	mpcdemo.Field("to", fmt.Sprintf("%s (%s)", destAddr, btcutil.Amount(pay)))
	mpcdemo.Field("sighash", hex.EncodeToString(sighash))

	mpcdemo.Step(6, "Threshold signing (parties 1 and 3)")
	sig, err := mpcdemo.DKLS23Sign(signers(keyshares), [32]byte(sighash))
	if err != nil {
		return err
	}
	der, err := mpcdemo.DERSignature(sig)
	if err != nil {
		return err
	}
	bitcoin.AttachSignature(tx, der, txscript.SigHashAll, pub)
	mpcdemo.Field("signature", hex.EncodeToString(sig))

	mpcdemo.Step(7, "Local verification and signed transaction")
	prevScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return err
	}
	if err := mpcdemo.VerifyInput(tx, prevScript, in.Value); err != nil {
		return err
	}
	mpcdemo.Field("btcd script engine", "valid")
	raw, err := mpcdemo.SerializeTx(tx)
	if err != nil {
		return err
	}
	mpcdemo.Field("txid", tx.TxHash())
	return finish(o, "raw tx", hex.EncodeToString(raw), func() (string, error) {
		body, err := httpDo(http.MethodPost, api+"/tx", "text/plain", []byte(hex.EncodeToString(raw)))
		return strings.TrimSpace(string(body)), err
	}, func(id string) string { return network.explorer + "/tx/" + id })
}

// btcDestination returns the witness program of a test network P2WPKH
// address. BuildP2WPKH only pays to P2WPKH outputs.
func btcDestination(s string) ([]byte, error) {
	a, err := btcutil.DecodeAddress(s, btcParams)
	if err != nil {
		return nil, err
	}
	if !a.IsForNet(btcParams) {
		return nil, errors.New("not a test network address")
	}
	w, ok := a.(*btcutil.AddressWitnessPubKeyHash)
	if !ok {
		return nil, errors.New("only P2WPKH (tb1q..., 42 chars) destinations are supported by pkg/chain/bitcoin.BuildP2WPKH")
	}
	return w.Hash160()[:], nil
}
