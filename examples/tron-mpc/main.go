// Command tron-mpc creates a 2-of-2 DKLs23 key, derives its Tron address,
// builds a TRX transfer (protobuf raw_data), signs sha256(raw_data) with the
// threshold protocol and verifies the result by recovering the signer's Tron
// address from the signature.
//
// The reference block is a placeholder; a broadcastable transaction needs
// ref_block_bytes/ref_block_hash from a recent block.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/evm"
	"github.com/didenkolab/mpc-sdk/pkg/chain/tron"
)

func main() {
	mpcdemo.Run("Tron: DKLs23 2-of-2, TRX transfer", run)
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
	from, err := tron.DeriveAddress(pub)
	if err != nil {
		return err
	}
	mpcdemo.Field("Tron address", from)

	mpcdemo.Step(3, "Unsigned TRX transfer")
	const to = "TLBaRhANQoJFTqre9Nf1mjuwNWjCJeYqUL"
	const amountSun = 1_000_000 // 1 TRX
	now := time.Now()
	tx, rawData, err := tron.BuildTRXTransfer(from, to, amountSun,
		"0d3a", "8fa9e75800000000", // placeholder reference block
		now.Add(time.Hour).UnixMilli(), now.UnixMilli())
	if err != nil {
		return err
	}
	hash := sha256.Sum256(rawData) // also the Tron transaction ID
	mpcdemo.Field("to", to)
	mpcdemo.Field("amount", "1 TRX")
	mpcdemo.Field("txID", hex.EncodeToString(hash[:]))

	mpcdemo.Step(4, "Threshold signing")
	sig, err := mpcdemo.DKLS23Sign(keyshares, hash)
	if err != nil {
		return err
	}
	// Tron uses the same 65-byte r||s||v recoverable signature as Ethereum.
	sig65, err := evm.BuildSignature65(hash, pub, hex.EncodeToString(sig))
	if err != nil {
		return err
	}
	mpcdemo.Field("signature", hex.EncodeToString(sig65))

	mpcdemo.Step(5, "Verification")
	recovered, err := crypto.SigToPub(hash[:], sig65)
	if err != nil {
		return fmt.Errorf("recover public key: %w", err)
	}
	recoveredAddr, err := tron.DeriveAddress(crypto.CompressPubkey(recovered))
	if err != nil {
		return err
	}
	if recoveredAddr != from {
		return fmt.Errorf("signature recovers to %s, want %s", recoveredAddr, from)
	}
	mpcdemo.Field("recovered signer", recoveredAddr)

	mpcdemo.Step(6, "Signed transaction")
	tron.AttachSignature(tx, sig65)
	txJSON, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	mpcdemo.Field("raw_data_hex", hex.EncodeToString(rawData))
	mpcdemo.Field("JSON", string(txJSON))

	mpcdemo.Done("signature recovers to the MPC Tron address")
	return nil
}
