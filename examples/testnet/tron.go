package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/evm"
	"github.com/didenkolab/mpc-sdk/pkg/chain/tron"
)

type tronNetwork struct {
	name     string
	explorer string
	faucet   string
}

// tronNetworks is an allowlist keyed by the block 0 ID; mainnet
// (00000000000000001ebf88508a03865c71d452e25f4d51194196a1d22b6653dc) is refused.
var tronNetworks = map[string]tronNetwork{
	"0000000000000000d698d4192c56cb6be724a558448e2684802de4d6cd8690dc": {
		"Nile", "https://nile.tronscan.org/#/transaction/", "https://nileex.io/join/getJoinPage",
	},
	"0000000000000000de1aa88295e1fcf982742f773e0419c5a9c134c994a9059e": {
		"Shasta", "https://shasta.tronscan.org/#/transaction/", "https://shasta.tronex.io (or the TronGrid Discord faucet)",
	},
}

const (
	tronDefaultAPI    = "https://nile.trongrid.io"
	tronDefaultAmount = 1_000_000 // sun = 1 TRX
)

type tronBlock struct {
	BlockID     string `json:"blockID"`
	BlockHeader struct {
		RawData struct {
			Number    int64 `json:"number"`
			Timestamp int64 `json:"timestamp"`
		} `json:"raw_data"`
	} `json:"block_header"`
}

func runTron(keyshares []string, o options) error {
	api := tronDefaultAPI
	if o.rpc != "" {
		api = strings.TrimRight(o.rpc, "/")
	}

	pub, err := mpcdemo.DKLS23PublicKey(keyshares[0])
	if err != nil {
		return err
	}
	from, err := tron.DeriveAddress(pub)
	if err != nil {
		return err
	}
	mpcdemo.Step(2, "Threshold address")
	mpcdemo.Field("public key", hex.EncodeToString(pub))
	mpcdemo.Field("address", from)

	mpcdemo.Step(3, "Network check")
	var genesis tronBlock
	if err := postJSON(api+"/wallet/getblockbynum", map[string]int{"num": 0}, &genesis); err != nil {
		return err
	}
	net, ok := tronNetworks[genesis.BlockID]
	if !ok {
		return fmt.Errorf("%s has genesis block %q, which is not Nile or Shasta (mainnet is refused)", api, genesis.BlockID)
	}
	mpcdemo.Field("API", api)
	mpcdemo.Field("network", net.name)

	if o.to == from {
		return errors.New("-to is the threshold address itself; Tron rejects transfers to yourself")
	}
	amount, err := amountUint64(o.amount, tronDefaultAmount)
	if err != nil {
		return err
	}

	mpcdemo.Step(4, "Chain data")
	var acct struct {
		Balance uint64 `json:"balance"`
	}
	if err := postJSON(api+"/wallet/getaccount", map[string]any{"address": from, "visible": true}, &acct); err != nil {
		return err
	}
	mpcdemo.Field("balance", fmt.Sprintf("%d sun", acct.Balance))
	if acct.Balance < amount {
		if !o.assumeFunded {
			return faucetHint(from, net.faucet+" (enter the address; Nile pays 2000 TRX)",
				"funds are usable after ~1 block (3 s); transfers use free daily bandwidth")
		}
		mpcdemo.Field("ASSUMED BALANCE", "address is unfunded (-assume-funded); the node would reject this transaction")
	}
	if o.to == "" {
		return errors.New("tron needs -to <T... address>: the network rejects transfers to the sender's own address")
	}
	var head tronBlock
	if err := postJSON(api+"/wallet/getnowblock", map[string]any{}, &head); err != nil {
		return err
	}
	refBytes, refHash, err := tronRefBlock(head)
	if err != nil {
		return err
	}
	mpcdemo.Field("reference block", fmt.Sprintf("#%d %s", head.BlockHeader.RawData.Number, head.BlockID))

	mpcdemo.Step(5, "Unsigned transaction")
	now := time.Now()
	tx, rawData, err := tron.BuildTRXTransfer(from, o.to, amount, refBytes, refHash,
		now.Add(10*time.Minute).UnixMilli(), now.UnixMilli())
	if err != nil {
		return err
	}
	txID := sha256.Sum256(rawData)
	mpcdemo.Field("to", fmt.Sprintf("%s (%d sun)", o.to, amount))
	mpcdemo.Field("txID", hex.EncodeToString(txID[:]))
	if acct.Balance >= amount {
		if err := tronCrossCheck(api, from, o.to, amount); err != nil {
			return err
		}
		mpcdemo.Field("node cross-check", "raw_data identical to the node-built transaction")
	} else {
		mpcdemo.Field("node cross-check", "skipped (the node only builds transactions for funded accounts)")
	}

	mpcdemo.Step(6, "Threshold signing (parties 1 and 3)")
	sig, err := mpcdemo.DKLS23Sign(signers(keyshares), txID)
	if err != nil {
		return err
	}
	sig65, err := evm.BuildSignature65(txID, pub, hex.EncodeToString(sig))
	if err != nil {
		return err
	}
	tron.AttachSignature(tx, sig65)
	mpcdemo.Field("signature", hex.EncodeToString(sig65))

	mpcdemo.Step(7, "Local verification and signed transaction")
	recovered, err := crypto.SigToPub(txID[:], sig65)
	if err != nil {
		return fmt.Errorf("recover public key: %w", err)
	}
	signer, err := tron.DeriveAddress(crypto.CompressPubkey(recovered))
	if err != nil {
		return err
	}
	if signer != from {
		return fmt.Errorf("signature recovers to %s, want %s", signer, from)
	}
	mpcdemo.Field("recovered signer", signer+" (matches)")
	signedHex := hex.EncodeToString(tronTransactionProto(rawData, sig65))

	return finish(o, "signed tx (protobuf hex)", signedHex, func() (string, error) {
		var res struct {
			Result  bool   `json:"result"`
			Code    string `json:"code"`
			Message string `json:"message"`
			TxID    string `json:"txid"`
		}
		if err := postJSON(api+"/wallet/broadcasthex", map[string]string{"transaction": signedHex}, &res); err != nil {
			return "", err
		}
		if !res.Result {
			msg := res.Message
			if b, err := hex.DecodeString(msg); err == nil {
				msg = string(b)
			}
			return "", fmt.Errorf("rejected: %s %s", res.Code, msg)
		}
		return hex.EncodeToString(txID[:]), nil
	}, func(id string) string { return net.explorer + id })
}

// tronRefBlock returns ref_block_bytes (bytes 6..8 of the big-endian block
// number) and ref_block_hash (bytes 8..16 of the block ID), both hex.
func tronRefBlock(b tronBlock) (string, string, error) {
	id, err := hex.DecodeString(b.BlockID)
	if err != nil || len(id) != 32 {
		return "", "", fmt.Errorf("invalid block ID %q", b.BlockID)
	}
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(b.BlockHeader.RawData.Number))
	return hex.EncodeToString(num[6:8]), hex.EncodeToString(id[8:16]), nil
}

// tronTransactionProto encodes protocol.Transaction{raw_data = 1,
// signature = 2} around the raw_data bytes produced by pkg/chain/tron.
func tronTransactionProto(rawData, sig []byte) []byte {
	out := []byte{0x0a}
	out = binary.AppendUvarint(out, uint64(len(rawData)))
	out = append(out, rawData...)
	out = append(out, 0x12)
	out = binary.AppendUvarint(out, uint64(len(sig)))
	return append(out, sig...)
}

// tronCrossCheck asks the node to build the same transfer (createtransaction
// is read-only: it returns an unsigned transaction and broadcasts nothing),
// rebuilds it with pkg/chain/tron from the node's reference block and
// timestamps, and requires identical raw_data bytes. A mismatch means the
// SDK's protobuf encoding differs from what the network expects.
func tronCrossCheck(api, from, to string, amount uint64) error {
	var node struct {
		Error   string `json:"Error"`
		RawData struct {
			RefBlockBytes string `json:"ref_block_bytes"`
			RefBlockHash  string `json:"ref_block_hash"`
			Expiration    int64  `json:"expiration"`
			Timestamp     int64  `json:"timestamp"`
		} `json:"raw_data"`
		RawDataHex string `json:"raw_data_hex"`
	}
	req := map[string]any{"owner_address": from, "to_address": to, "amount": amount, "visible": true}
	if err := postJSON(api+"/wallet/createtransaction", req, &node); err != nil {
		return fmt.Errorf("node cross-check: %w", err)
	}
	if node.Error != "" || node.RawDataHex == "" {
		return fmt.Errorf("node cross-check: createtransaction: %s", node.Error)
	}
	r := node.RawData
	_, sdkRaw, err := tron.BuildTRXTransfer(from, to, amount, r.RefBlockBytes, r.RefBlockHash, r.Expiration, r.Timestamp)
	if err != nil {
		return fmt.Errorf("node cross-check: %w", err)
	}
	if got := hex.EncodeToString(sdkRaw); got != node.RawDataHex {
		return fmt.Errorf("node cross-check: pkg/chain/tron raw_data differs from the node's encoding of the same transfer\n   node: %s\n   sdk:  %s", node.RawDataHex, got)
	}
	return nil
}
