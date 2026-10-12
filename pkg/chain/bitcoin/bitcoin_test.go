package bitcoin

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func TestDeriveP2WPKHAddress(t *testing.T) {
	// Sample compressed pubkey (33 bytes)
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}

	addr, err := DeriveP2WPKHAddress(pubBytes, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("derive P2WPKH address: %v", err)
	}

	if addr == nil {
		t.Fatalf("address is nil")
	}

	addrStr := addr.EncodeAddress()
	if len(addrStr) == 0 {
		t.Fatalf("empty address string")
	}

	// Check if it's a valid Bech32 address (starts with tb1 for testnet)
	if addrStr[:3] != "tb1" {
		t.Fatalf("expected testnet P2WPKH address to start with 'tb1', got: %s", addrStr)
	}
}

func TestDeriveP2PKHAddress(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}

	addr, err := DeriveP2PKHAddress(pubBytes, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("derive P2PKH address: %v", err)
	}

	if addr == nil {
		t.Fatalf("address is nil")
	}

	addrStr := addr.EncodeAddress()
	if len(addrStr) == 0 {
		t.Fatalf("empty address string")
	}

	// Check if it's a valid legacy address (starts with m or n for testnet)
	if addrStr[0] != 'm' && addrStr[0] != 'n' {
		t.Fatalf("expected testnet P2PKH address to start with 'm' or 'n', got: %s", addrStr)
	}
}

func TestDeriveP2SHAddress(t *testing.T) {
	// Sample redeem script
	redeemScript := []byte{0x51} // OP_1 (anyone can spend for testing)

	addr, err := DeriveP2SHAddress(redeemScript, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("derive P2SH address: %v", err)
	}

	if addr == nil {
		t.Fatalf("address is nil")
	}

	addrStr := addr.EncodeAddress()
	if len(addrStr) == 0 {
		t.Fatalf("empty address string")
	}

	// Check if it's a valid P2SH address (starts with 2 for testnet)
	if addrStr[0] != '2' {
		t.Fatalf("expected testnet P2SH address to start with '2', got: %s", addrStr)
	}
}

func TestBuildP2WPKH(t *testing.T) {
	// Sample data for testing
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	pkHash, err := Hash160Compressed(pubBytes)
	if err != nil {
		t.Fatalf("hash160: %v", err)
	}

	utxo := UTXO{
		TxID:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		Vout:   0,
		Amount: 100000000, // 1 BTC in sats
		PkHash: pkHash,
	}

	payment := Payment{
		ToPkHash: pkHash,
		Amount:   50000000, // 0.5 BTC
		ChangePk: pkHash,
		Fee:      1000, // 1000 sats
	}

	tx, sighash, err := BuildP2WPKH(utxo, payment, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("build P2WPKH tx: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(sighash) != 32 {
		t.Fatalf("expected 32-byte sighash, got %d bytes", len(sighash))
	}

	// Check transaction structure
	if len(tx.TxIn) != 1 {
		t.Fatalf("expected 1 input, got %d", len(tx.TxIn))
	}

	if len(tx.TxOut) != 2 {
		t.Fatalf("expected 2 outputs (payment + change), got %d", len(tx.TxOut))
	}

	// Check amounts
	totalOut := tx.TxOut[0].Value + tx.TxOut[1].Value
	expectedOut := payment.Amount + (utxo.Amount - payment.Amount - payment.Fee)
	if totalOut != expectedOut {
		t.Fatalf("amount mismatch: got %d, expected %d", totalOut, expectedOut)
	}
}

func TestBuildP2PKH(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	pkHash, err := Hash160Compressed(pubBytes)
	if err != nil {
		t.Fatalf("hash160: %v", err)
	}

	utxo := UTXO{
		TxID:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		Vout:   0,
		Amount: 100000000, // 1 BTC in sats
		PkHash: pkHash,
	}

	payment := Payment{
		ToPkHash: pkHash,
		Amount:   50000000, // 0.5 BTC
		ChangePk: pkHash,
		Fee:      1000, // 1000 sats
	}

	tx, sighash, err := BuildP2PKH(utxo, payment, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("build P2PKH tx: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(sighash) != 32 {
		t.Fatalf("expected 32-byte sighash, got %d bytes", len(sighash))
	}

	// Check transaction structure
	if len(tx.TxIn) != 1 {
		t.Fatalf("expected 1 input, got %d", len(tx.TxIn))
	}

	if len(tx.TxOut) != 2 {
		t.Fatalf("expected 2 outputs (payment + change), got %d", len(tx.TxOut))
	}
}

func TestAttachP2PKHSignature(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	pkHash, _ := Hash160Compressed(pubBytes)

	utxo := UTXO{
		TxID:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		Vout:   0,
		Amount: 100000000,
		PkHash: pkHash,
	}

	payment := Payment{
		ToPkHash: pkHash,
		Amount:   50000000,
		ChangePk: pkHash,
		Fee:      1000,
	}

	tx, _, err := BuildP2PKH(utxo, payment, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatalf("build P2PKH tx: %v", err)
	}

	// Dummy DER signature (this would normally come from ECDSA signing)
	derSig := []byte{0x30, 0x44, 0x02, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		0x02, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
		0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40}

	err = AttachP2PKHSignature(tx, derSig, 0x01, pubBytes)
	if err != nil {
		t.Fatalf("attach P2PKH signature: %v", err)
	}

	if len(tx.TxIn[0].SignatureScript) == 0 {
		t.Fatalf("signature script is empty")
	}

	// Verify script structure: signature + pubkey
	script := tx.TxIn[0].SignatureScript
	if len(script) < 100 { // rough minimum for sig + pubkey
		t.Fatalf("signature script too short: %d bytes", len(script))
	}
}

func TestHash160Compressed(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}

	hash, err := Hash160Compressed(pubBytes)
	if err != nil {
		t.Fatalf("hash160: %v", err)
	}

	if len(hash) != 20 {
		t.Fatalf("expected 20-byte hash, got %d bytes", len(hash))
	}

	// Test invalid input
	_, err = Hash160Compressed([]byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid pubkey length")
	}
}

// signAndVerify signs sighash with key, lets attach place the signature into
// tx, and runs the btcd script engine against the spent output.
func signAndVerify(t *testing.T, tx *wire.MsgTx, sighash []byte, key *btcec.PrivateKey,
	prevPkScript []byte, amount int64, attach func(der []byte) error) {
	t.Helper()
	der := ecdsa.Sign(key, sighash).Serialize()
	if err := attach(der); err != nil {
		t.Fatalf("attach signature: %v", err)
	}
	fetcher := txscript.NewCannedPrevOutputFetcher(prevPkScript, amount)
	vm, err := txscript.NewEngine(prevPkScript, tx, 0, txscript.StandardVerifyFlags, nil,
		txscript.NewTxSigHashes(tx, fetcher), amount, fetcher)
	if err != nil {
		t.Fatalf("new script engine: %v", err)
	}
	if err := vm.Execute(); err != nil {
		t.Fatalf("script validation failed: %v", err)
	}
}

// TestSpendToOtherAddressValidates is a regression test: the sighash must
// commit to the spent output, not the recipient, so a spend to a different
// address has to pass consensus script validation.
func TestSpendToOtherAddressValidates(t *testing.T) {
	net := &chaincfg.MainNetParams
	key, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PubKey().SerializeCompressed()
	pkHash := btcutil.Hash160(pub)

	// Payload of 1BoatSLRHtKNngkdXEeobR76b53LETtpyT, a third-party address.
	dest, err := btcutil.DecodeAddress("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", net)
	if err != nil {
		t.Fatal(err)
	}
	utxo := UTXO{TxID: strings.Repeat("ab", 32), Vout: 1, Amount: 100_000, PkHash: pkHash}

	for name, pay := range map[string]Payment{
		"with change":    {ToPkHash: dest.ScriptAddress(), Amount: 60_000, ChangePk: pkHash, Fee: 1_000},
		"without change": {ToPkHash: dest.ScriptAddress(), Amount: 99_000, ChangePk: pkHash, Fee: 1_000},
	} {
		t.Run("P2WPKH "+name, func(t *testing.T) {
			tx, sighash, err := BuildP2WPKH(utxo, pay, net)
			if err != nil {
				t.Fatal(err)
			}
			prev, err := txscript.PayToAddrScript(addrFromPkHash(pkHash, net))
			if err != nil {
				t.Fatal(err)
			}
			signAndVerify(t, tx, sighash, key, prev, utxo.Amount, func(der []byte) error {
				AttachSignature(tx, der, txscript.SigHashAll, pub)
				return nil
			})
		})

		t.Run("P2PKH "+name, func(t *testing.T) {
			tx, sighash, err := BuildP2PKH(utxo, pay, net)
			if err != nil {
				t.Fatal(err)
			}
			addr, err := btcutil.NewAddressPubKeyHash(pkHash, net)
			if err != nil {
				t.Fatal(err)
			}
			prev, err := txscript.PayToAddrScript(addr)
			if err != nil {
				t.Fatal(err)
			}
			signAndVerify(t, tx, sighash, key, prev, utxo.Amount, func(der []byte) error {
				return AttachP2PKHSignature(tx, der, txscript.SigHashAll, pub)
			})
		})
	}

	t.Run("wrong key is rejected", func(t *testing.T) {
		other, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pay := Payment{ToPkHash: dest.ScriptAddress(), Amount: 60_000, ChangePk: pkHash, Fee: 1_000}
		tx, sighash, err := BuildP2WPKH(utxo, pay, net)
		if err != nil {
			t.Fatal(err)
		}
		prev, _ := txscript.PayToAddrScript(addrFromPkHash(pkHash, net))
		AttachSignature(tx, ecdsa.Sign(other, sighash).Serialize(), txscript.SigHashAll, pub)
		fetcher := txscript.NewCannedPrevOutputFetcher(prev, utxo.Amount)
		vm, err := txscript.NewEngine(prev, tx, 0, txscript.StandardVerifyFlags, nil,
			txscript.NewTxSigHashes(tx, fetcher), utxo.Amount, fetcher)
		if err != nil {
			t.Fatal(err)
		}
		if err := vm.Execute(); err == nil {
			t.Fatal("signature from a different key passed validation")
		}
	})
}
