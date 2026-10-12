// Command solana-frost-mpc creates a 2-of-3 FROST (Ed25519) key, derives its
// Solana address, builds a SOL transfer, signs the serialized message with two
// of the three parties and verifies the signature with the standard library
// before assembling the signed transaction.
//
// The recent blockhash is a placeholder; a broadcastable transaction needs a
// current blockhash from an RPC node.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/blocto/solana-go-sdk/common"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/solana"
)

func main() {
	mpcdemo.Run("Solana: FROST 2-of-3, SOL transfer", run)
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
	mpcdemo.Field("public key (hex)", hex.EncodeToString(pub))

	mpcdemo.Step(2, "Address")
	from, err := solana.DeriveAddress(pub)
	if err != nil {
		return err
	}
	mpcdemo.Field("Solana address", from.ToBase58())

	mpcdemo.Step(3, "Transfer message")
	to := common.PublicKeyFromString("9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM")
	const lamports = 100_000_000                                                                            // 0.1 SOL
	msg, err := solana.BuildTransferSOL(from, to, lamports, "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N") // placeholder blockhash
	if err != nil {
		return err
	}
	raw, err := msg.Serialize()
	if err != nil {
		return err
	}
	mpcdemo.Field("transfer", "0.1 SOL to "+to.ToBase58())
	mpcdemo.Field("message", fmt.Sprintf("%d bytes", len(raw)))

	// Solana signs the serialized message itself (Ed25519 hashes internally).
	mpcdemo.Step(4, "Threshold signing (parties 2 and 3)")
	sig, err := solana.SignMessageWithFROST(msg, []string{keyshares[1], keyshares[2]}, 2)
	if err != nil {
		return err
	}
	mpcdemo.Field("signature", hex.EncodeToString(sig))

	mpcdemo.Step(5, "Verification")
	if err := mpcdemo.VerifyEd25519(pub, raw, sig); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	mpcdemo.Field("Ed25519", "valid")

	mpcdemo.Step(6, "Signed transaction")
	tx, err := solana.AssembleTransaction(msg, sig, from)
	if err != nil {
		return err
	}
	wire, err := tx.Serialize()
	if err != nil {
		return err
	}
	mpcdemo.Field("base64 (for RPC)", base64.StdEncoding.EncodeToString(wire))

	mpcdemo.Done("signature by 2 of 3 parties verifies against the group key")
	return nil
}
