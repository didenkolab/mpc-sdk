package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/near"
)

const nearDefaultRPC = "https://rpc.testnet.fastnear.com"

var (
	nearDefaultAmount = new(big.Int).Exp(big.NewInt(10), big.NewInt(21), nil) // 0.001 NEAR in yocto
	nearFeeReserve    = new(big.Int).Exp(big.NewInt(10), big.NewInt(22), nil) // 0.01 NEAR for gas
	nearAccountID     = regexp.MustCompile(`^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$`)
)

func runNEAR(keyshares []string, o options) error {
	url := o.rpc
	if url == "" {
		url = nearDefaultRPC
	}

	pub, err := mpcdemo.FROSTPublicKey(keyshares[0])
	if err != nil {
		return err
	}
	account, err := near.DeriveImplicitAddress(pub)
	if err != nil {
		return err
	}
	pubKey := "ed25519:" + near.EncodeBase58(pub)
	mpcdemo.Step(2, "Threshold account")
	mpcdemo.Field("implicit account", account)
	mpcdemo.Field("public key", pubKey)

	mpcdemo.Step(3, "Network check")
	var status struct {
		ChainID string `json:"chain_id"`
	}
	if err := jsonRPC(url, "status", []any{}, &status); err != nil {
		return err
	}
	if status.ChainID != "testnet" {
		return fmt.Errorf("%s reports chain_id %q; only testnet is allowed", url, status.ChainID)
	}
	mpcdemo.Field("RPC", url)
	mpcdemo.Field("chain_id", status.ChainID)

	to := account
	if o.to != "" {
		if len(o.to) < 2 || len(o.to) > 64 || !nearAccountID.MatchString(o.to) {
			return fmt.Errorf("-to %q is not a NEAR account ID", o.to)
		}
		to = o.to
	}
	amount, err := amountOr(o.amount, nearDefaultAmount)
	if err != nil {
		return err
	}

	mpcdemo.Step(4, "Chain data")
	var acct struct {
		Amount string `json:"amount"`
	}
	balance := new(big.Int)
	var nonce uint64
	err = jsonRPC(url, "query", map[string]any{
		"request_type": "view_account", "finality": "final", "account_id": account,
	}, &acct)
	switch {
	case err == nil:
		if _, ok := balance.SetString(acct.Amount, 10); !ok {
			return fmt.Errorf("view_account: bad amount %q", acct.Amount)
		}
		var key struct {
			Nonce uint64 `json:"nonce"`
			Error string `json:"error"`
		}
		if err := jsonRPC(url, "query", map[string]any{
			"request_type": "view_access_key", "finality": "final", "account_id": account, "public_key": pubKey,
		}, &key); err != nil {
			return err
		}
		if key.Error != "" {
			return fmt.Errorf("view_access_key: %s", key.Error)
		}
		nonce = key.Nonce
	case isRPCError(err):
		// UNKNOWN_ACCOUNT: an implicit account exists only after it is funded.
		mpcdemo.Field("account", "does not exist yet")
	default:
		return err
	}
	need := new(big.Int).Add(amount, nearFeeReserve)
	mpcdemo.Field("balance", balance.String()+" yoctoNEAR")
	mpcdemo.Field("access key nonce", nonce)
	if balance.Cmp(need) < 0 {
		if !o.assumeFunded {
			return faucetHint(account,
				"https://near-faucet.io (testnet; paste the 64-hex implicit account), or",
				"create a funded testnet account with near-cli-rs: near account create-account sponsor-by-faucet-service <name>.testnet ...",
				"then: near tokens <name>.testnet send-near "+account+" '1 NEAR' network-config testnet sign-with-keychain send",
				"funds are usable after ~1 block (1 s)")
		}
		mpcdemo.Field("ASSUMED BALANCE", "account is unfunded (-assume-funded); the network would reject this transaction")
	}
	var block struct {
		Header struct {
			Height uint64 `json:"height"`
			Hash   string `json:"hash"`
		} `json:"header"`
	}
	if err := jsonRPC(url, "block", map[string]string{"finality": "final"}, &block); err != nil {
		return err
	}
	blockHash, err := near.DecodeBase58(block.Header.Hash)
	if err != nil || len(blockHash) != 32 {
		return fmt.Errorf("invalid block hash %q", block.Header.Hash)
	}
	mpcdemo.Field("recent block", fmt.Sprintf("#%d %s", block.Header.Height, block.Header.Hash))

	mpcdemo.Step(5, "Unsigned transaction")
	tx, serialized, err := near.BuildTransferTransaction(account, to, amount, nonce+1, blockHash, pub, true)
	if err != nil {
		return err
	}
	hash := near.HashTransaction(serialized)
	mpcdemo.Field("to", fmt.Sprintf("%s (%s yoctoNEAR)", to, amount))
	mpcdemo.Field("sha256(tx)", hex.EncodeToString(hash[:]))

	mpcdemo.Step(6, "Threshold signing (parties 1 and 3)")
	sig, err := mpcdemo.FROSTSign(signers(keyshares), hash[:])
	if err != nil {
		return err
	}
	mpcdemo.Field("signature", hex.EncodeToString(sig))

	mpcdemo.Step(7, "Local verification and signed transaction")
	if err := mpcdemo.VerifyEd25519(pub, hash[:], sig); err != nil {
		return err
	}
	mpcdemo.Field("crypto/ed25519", "valid")
	signed, err := near.AttachSignature(tx, sig)
	if err != nil {
		return err
	}
	b64, err := near.EncodeSignedTransactionBase64(signed)
	if err != nil {
		return err
	}
	txHash := near.EncodeBase58(hash[:])
	mpcdemo.Field("tx hash", txHash)

	return finish(o, "base64 tx", b64, func() (string, error) {
		var res struct {
			Status      map[string]any `json:"status"`
			Transaction struct {
				Hash string `json:"hash"`
			} `json:"transaction"`
		}
		err := jsonRPC(url, "send_tx", map[string]string{
			"signed_tx_base64": b64, "wait_until": "EXECUTED_OPTIMISTIC",
		}, &res)
		if err != nil {
			return "", err
		}
		if f, ok := res.Status["Failure"]; ok {
			return "", fmt.Errorf("transaction %s failed: %v", res.Transaction.Hash, f)
		}
		if res.Transaction.Hash == "" {
			return "", errors.New("send_tx: no transaction hash in response")
		}
		return res.Transaction.Hash, nil
	}, func(id string) string { return "https://testnet.nearblocks.io/txns/" + id })
}
