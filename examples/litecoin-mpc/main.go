// Command litecoin-mpc creates a 2-of-2 DKLs23 key, derives Litecoin mainnet
// addresses from it, builds legacy (P2PKH) and SegWit (P2WPKH) self-spends,
// signs both with the threshold protocol and validates the signed transactions
// with the script engine (Litecoin shares Bitcoin's script rules).
//
// The input UTXO is a placeholder, so the transactions are not broadcastable
// as-is.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/litecoin"
)

func main() {
	mpcdemo.Run("Litecoin: DKLs23 2-of-2, P2PKH and P2WPKH", run)
}

func run() error {
	net := litecoin.GetMainnetParams()

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
	p2pkh, err := litecoin.DeriveP2PKHAddress(pub, net)
	if err != nil {
		return err
	}
	p2wpkh, err := litecoin.DeriveP2WPKHAddress(pub, net)
	if err != nil {
		return err
	}
	mpcdemo.Field("P2PKH", p2pkh.EncodeAddress())
	mpcdemo.Field("P2WPKH", p2wpkh.EncodeAddress())

	mpcdemo.Step(3, "Unsigned transactions (self-spend)")
	pkHash, err := litecoin.Hash160Compressed(pub)
	if err != nil {
		return err
	}
	utxo := litecoin.UTXO{
		TxID:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", // placeholder
		Vout:   0,
		Amount: 100_000_000, // 1 LTC
		PkHash: pkHash,
	}
	payment := litecoin.Payment{ToPkHash: pkHash, Amount: 50_000_000, ChangePk: pkHash, Fee: 1_000}

	legacyTx, legacyHash, err := litecoin.BuildP2PKH(utxo, payment, net)
	if err != nil {
		return fmt.Errorf("build P2PKH: %w", err)
	}
	segwitTx, segwitHash, err := litecoin.BuildP2WPKH(utxo, payment, net)
	if err != nil {
		return fmt.Errorf("build P2WPKH: %w", err)
	}
	mpcdemo.Field("input", fmt.Sprintf("%s:%d (%d litoshi)", utxo.TxID, utxo.Vout, utxo.Amount))
	mpcdemo.Field("payment", fmt.Sprintf("%d litoshi", payment.Amount))
	mpcdemo.Field("fee", fmt.Sprintf("%d litoshi", payment.Fee))
	mpcdemo.Field("P2PKH sighash", hex.EncodeToString(legacyHash))
	mpcdemo.Field("P2WPKH sighash", hex.EncodeToString(segwitHash))

	mpcdemo.Step(4, "Threshold signing")
	legacySig, err := signDER(keyshares, legacyHash)
	if err != nil {
		return fmt.Errorf("sign P2PKH: %w", err)
	}
	if err := litecoin.AttachP2PKHSignature(legacyTx, legacySig, txscript.SigHashAll, pub); err != nil {
		return err
	}
	segwitSig, err := signDER(keyshares, segwitHash)
	if err != nil {
		return fmt.Errorf("sign P2WPKH: %w", err)
	}
	if err := litecoin.AttachP2WPKHSignature(segwitTx, segwitSig, txscript.SigHashAll, pub); err != nil {
		return err
	}
	mpcdemo.Field("P2PKH signature", hex.EncodeToString(legacySig))
	mpcdemo.Field("P2WPKH signature", hex.EncodeToString(segwitSig))

	mpcdemo.Step(5, "Script validation")
	if err := verify(legacyTx, p2pkh, utxo.Amount); err != nil {
		return fmt.Errorf("P2PKH: %w", err)
	}
	mpcdemo.Field("P2PKH", "valid")
	if err := verify(segwitTx, p2wpkh, utxo.Amount); err != nil {
		return fmt.Errorf("P2WPKH: %w", err)
	}
	mpcdemo.Field("P2WPKH", "valid")

	mpcdemo.Step(6, "Signed transactions")
	for _, t := range []struct {
		label string
		tx    *wire.MsgTx
	}{{"P2PKH", legacyTx}, {"P2WPKH", segwitTx}} {
		raw, err := mpcdemo.SerializeTx(t.tx)
		if err != nil {
			return err
		}
		mpcdemo.Field(t.label+" txid", t.tx.TxHash())
		mpcdemo.Field(t.label+" raw", hex.EncodeToString(raw))
	}

	mpcdemo.Done("both transactions pass script validation")
	return nil
}

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

func verify(tx *wire.MsgTx, spent btcutil.Address, amount int64) error {
	script, err := txscript.PayToAddrScript(spent)
	if err != nil {
		return err
	}
	return mpcdemo.VerifyInput(tx, script, amount)
}
