// Command cosmos-mpc creates a 2-of-2 DKLs23 key, derives its Cosmos Hub
// address, builds a bank MsgSend sign document, signs SHA-256(sign bytes) with
// the threshold protocol and verifies the signature locally.
//
// Note: pkg/chain/cosmos encodes the SignDoc as JSON. A broadcastable
// SIGN_MODE_DIRECT transaction needs the protobuf encoding of TxBody, AuthInfo
// and SignDoc, so this example demonstrates the key, address and signature
// format rather than producing a transaction a node would accept.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/cosmos"
)

// generator is the compressed secp256k1 generator point. Its address serves
// as a valid, well-known recipient for the demo transfer.
const generator = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func main() {
	mpcdemo.Run("Cosmos Hub: DKLs23 2-of-2, bank MsgSend", run)
}

func run() error {
	mpcdemo.Step(1, "Distributed key generation")
	keyshares, err := mpcdemo.DKLS23Keygen(2, 2, nil)
	if err != nil {
		return err
	}
	pub, err := mpcdemo.DKLS23PublicKey(keyshares[0])
	if err != nil {
		return err
	}
	mpcdemo.Field("public key", hex.EncodeToString(pub))

	mpcdemo.Step(2, "Address")
	from, err := cosmos.DeriveAddress(pub, "cosmos")
	if err != nil {
		return err
	}
	mpcdemo.Field("Cosmos address", from)

	mpcdemo.Step(3, "Sign document")
	genPub, err := hex.DecodeString(generator)
	if err != nil {
		return err
	}
	to, err := cosmos.DeriveAddress(genPub, "cosmos")
	if err != nil {
		return err
	}
	amount := []cosmos.Coin{{Denom: "uatom", Amount: "1000000"}} // 1 ATOM
	fee := cosmos.Fee{Amount: []cosmos.Coin{{Denom: "uatom", Amount: "500"}}, GasLimit: 200_000}
	doc, err := cosmos.BuildTransferTx(from, to, amount, 1, 12345, "cosmoshub-4", fee, "MPC demo", pub)
	if err != nil {
		return err
	}
	signBytes, err := cosmos.SignBytes(doc)
	if err != nil {
		return err
	}
	hash := cosmos.HashSignDoc(signBytes)
	mpcdemo.Field("message", "MsgSend 1 ATOM to "+to)
	mpcdemo.Field("chain / account", "cosmoshub-4 / account 12345, sequence 1")
	mpcdemo.Field("sha256(sign bytes)", hex.EncodeToString(hash[:]))

	mpcdemo.Step(4, "Threshold signing")
	sig, err := mpcdemo.DKLS23Sign(keyshares, hash)
	if err != nil {
		return err
	}
	mpcdemo.Field("signature (base64)", base64.StdEncoding.EncodeToString(sig))

	mpcdemo.Step(5, "Verification")
	if err := mpcdemo.VerifyECDSA(pub, hash, sig); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	mpcdemo.Field("secp256k1 ECDSA", "valid")

	mpcdemo.Done("sign document signed and verified")
	return nil
}
