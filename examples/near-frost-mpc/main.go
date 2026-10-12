// Command near-frost-mpc creates a 2-of-3 FROST (Ed25519) key, derives the
// NEAR implicit account for it, builds a Borsh-encoded transfer, signs
// sha256(transaction) with two of the three parties and verifies the signature
// with the standard library before serializing the signed transaction.
//
// The block hash and nonce are placeholders; a broadcastable transaction needs
// a recent block hash and the access key's next nonce from an RPC node.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/near"
)

func main() {
	mpcdemo.Run("NEAR: FROST 2-of-3, transfer", run)
}

func run() error {
	mpcdemo.Step(1, "Distributed key generation (2-of-3)")
	keyshares, err := mpcdemo.FROSTKeygen(3, 2)
	if err != nil {
		return err
	}
	pub, err := mpcdemo.FROSTPublicKey(keyshares[0])
	if err != nil {
		return err
	}
	mpcdemo.Field("public key", "ed25519:"+near.EncodeBase58(pub))

	mpcdemo.Step(2, "Account")
	account, err := near.DeriveImplicitAddress(pub)
	if err != nil {
		return err
	}
	mpcdemo.Field("implicit account", account)

	mpcdemo.Step(3, "Unsigned transfer")
	const receiver = "receiver.testnet"
	blockHash, err := hex.DecodeString("5d6e1a345d6e1a345d6e1a345d6e1a345d6e1a345d6e1a345d6e1a345d6e1a34") // placeholder
	if err != nil {
		return err
	}
	tx, serialized, err := near.BuildTransferTransaction(account, receiver, near.ConvertNEARToYocto(1), 1, blockHash, pub, true)
	if err != nil {
		return err
	}
	hash := near.HashTransaction(serialized)
	mpcdemo.Field("transfer", "1 NEAR to "+receiver)
	mpcdemo.Field("sha256(tx)", hex.EncodeToString(hash[:]))

	mpcdemo.Step(4, "Threshold signing (parties 1 and 3)")
	sig, err := mpcdemo.FROSTSign([]string{keyshares[0], keyshares[2]}, hash[:])
	if err != nil {
		return err
	}
	mpcdemo.Field("signature", hex.EncodeToString(sig))

	mpcdemo.Step(5, "Verification")
	if err := mpcdemo.VerifyEd25519(pub, hash[:], sig); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	mpcdemo.Field("Ed25519", "valid")

	mpcdemo.Step(6, "Signed transaction")
	signed, err := near.AttachSignature(tx, sig)
	if err != nil {
		return err
	}
	b64, err := near.EncodeSignedTransactionBase64(signed)
	if err != nil {
		return err
	}
	mpcdemo.Field("base64 (for RPC)", b64)

	mpcdemo.Done("signature by 2 of 3 parties verifies against the group key")
	return nil
}
