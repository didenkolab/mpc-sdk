// Command bitcoin-mpc creates a 2-of-2 DKLs23 key, derives Bitcoin mainnet
// addresses from it, builds legacy (P2PKH) and SegWit (P2WPKH) spends, signs
// both with the threshold protocol and validates the signed transactions with
// the btcd script engine.
//
// The input UTXO is a placeholder: the signed transactions are valid against
// it, but they can only be broadcast after replacing it with a real output
// owned by the MPC address (see the flags).
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/bitcoin"
)

var (
	utxoTxID   = flag.String("utxo-txid", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "txid of the output to spend (placeholder by default)")
	utxoVout   = flag.Uint("utxo-vout", 0, "output index of the UTXO")
	utxoAmount = flag.Int64("utxo-amount", 100_000_000, "UTXO value in satoshis")
	payAmount  = flag.Int64("amount", 50_000_000, "payment amount in satoshis")
	fee        = flag.Int64("fee", 1_000, "fee in satoshis")
	toAddr     = flag.String("to", "", "P2PKH or P2WPKH destination (default: the MPC key itself)")
)

func main() {
	flag.Parse()
	mpcdemo.Run("Bitcoin: DKLs23 2-of-2, P2PKH and P2WPKH", run)
}

func run() error {
	net := &chaincfg.MainNetParams

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

	mpcdemo.Step(2, "Addresses")
	p2pkh, err := bitcoin.DeriveP2PKHAddress(pub, net)
	if err != nil {
		return err
	}
	p2wpkh, err := bitcoin.DeriveP2WPKHAddress(pub, net)
	if err != nil {
		return err
	}
	mpcdemo.Field("P2PKH", p2pkh.EncodeAddress())
	mpcdemo.Field("P2WPKH", p2wpkh.EncodeAddress())

	mpcdemo.Step(3, "Unsigned transactions")
	pkHash, err := bitcoin.Hash160Compressed(pub)
	if err != nil {
		return err
	}
	dest := pkHash
	if s := strings.TrimSpace(*toAddr); s != "" {
		if dest, err = pkHashFromAddress(s, net); err != nil {
			return fmt.Errorf("-to: %w", err)
		}
	}
	utxo := bitcoin.UTXO{TxID: *utxoTxID, Vout: uint32(*utxoVout), Amount: *utxoAmount, PkHash: pkHash}
	payment := bitcoin.Payment{ToPkHash: dest, Amount: *payAmount, ChangePk: pkHash, Fee: *fee}

	legacyTx, legacyHash, err := bitcoin.BuildP2PKH(utxo, payment, net)
	if err != nil {
		return fmt.Errorf("build P2PKH: %w", err)
	}
	segwitTx, segwitHash, err := bitcoin.BuildP2WPKH(utxo, payment, net)
	if err != nil {
		return fmt.Errorf("build P2WPKH: %w", err)
	}
	mpcdemo.Field("input", fmt.Sprintf("%s:%d (%s)", utxo.TxID, utxo.Vout, btcutil.Amount(utxo.Amount)))
	mpcdemo.Field("payment", btcutil.Amount(payment.Amount))
	mpcdemo.Field("fee", btcutil.Amount(payment.Fee))
	mpcdemo.Field("P2PKH sighash", hex.EncodeToString(legacyHash))
	mpcdemo.Field("P2WPKH sighash", hex.EncodeToString(segwitHash))

	mpcdemo.Step(4, "Threshold signing")
	legacySig, err := signDER(keyshares, legacyHash)
	if err != nil {
		return fmt.Errorf("sign P2PKH: %w", err)
	}
	if err := bitcoin.AttachP2PKHSignature(legacyTx, legacySig, txscript.SigHashAll, pub); err != nil {
		return err
	}
	segwitSig, err := signDER(keyshares, segwitHash)
	if err != nil {
		return fmt.Errorf("sign P2WPKH: %w", err)
	}
	bitcoin.AttachSignature(segwitTx, segwitSig, txscript.SigHashAll, pub)
	mpcdemo.Field("P2PKH signature", hex.EncodeToString(legacySig))
	mpcdemo.Field("P2WPKH signature", hex.EncodeToString(segwitSig))

	mpcdemo.Step(5, "Script validation")
	legacyScript, err := txscript.PayToAddrScript(p2pkh)
	if err != nil {
		return err
	}
	if err := mpcdemo.VerifyInput(legacyTx, legacyScript, utxo.Amount); err != nil {
		return fmt.Errorf("P2PKH: %w", err)
	}
	mpcdemo.Field("P2PKH", "valid")
	segwitScript, err := txscript.PayToAddrScript(p2wpkh)
	if err != nil {
		return err
	}
	if err := mpcdemo.VerifyInput(segwitTx, segwitScript, utxo.Amount); err != nil {
		return fmt.Errorf("P2WPKH: %w", err)
	}
	mpcdemo.Field("P2WPKH", "valid")

	mpcdemo.Step(6, "Signed transactions")
	if err := printTx("P2PKH", legacyTx); err != nil {
		return err
	}
	if err := printTx("P2WPKH", segwitTx); err != nil {
		return err
	}

	mpcdemo.Done("both transactions pass Bitcoin script validation")
	return nil
}

// signDER runs the threshold protocol on a sighash and returns a DER signature.
func signDER(keyshares []string, sighash []byte) ([]byte, error) {
	if len(sighash) != 32 {
		return nil, fmt.Errorf("sighash is %d bytes, want 32", len(sighash))
	}
	sig, err := mpcdemo.DKLS23Sign(keyshares, [32]byte(sighash))
	if err != nil {
		return nil, err
	}
	return mpcdemo.DERSignature(sig)
}

func printTx(label string, tx *wire.MsgTx) error {
	raw, err := mpcdemo.SerializeTx(tx)
	if err != nil {
		return err
	}
	mpcdemo.Field(label+" txid", tx.TxHash())
	mpcdemo.Field(label+" raw", hex.EncodeToString(raw))
	return nil
}

func pkHashFromAddress(addr string, net *chaincfg.Params) ([]byte, error) {
	parsed, err := btcutil.DecodeAddress(addr, net)
	if err != nil {
		return nil, err
	}
	switch a := parsed.(type) {
	case *btcutil.AddressPubKeyHash:
		return a.Hash160()[:], nil
	case *btcutil.AddressWitnessPubKeyHash:
		return a.Hash160()[:], nil
	default:
		return nil, errors.New("only P2PKH and P2WPKH addresses are supported")
	}
}
