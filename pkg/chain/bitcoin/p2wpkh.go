package bitcoin

import (
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

type UTXO struct {
	TxID   string
	Vout   uint32
	Amount int64 // in sats
	PkHash []byte
}

type Payment struct {
	ToPkHash []byte
	Amount   int64 // sats
	ChangePk []byte
	Fee      int64 // sats (simple fixed fee)
}

// BuildP2WPKH creates a transaction spending one P2WPKH output (u) to a P2WPKH
// recipient, with optional change, and returns it with the BIP143 sighash to
// sign with ECDSA.
func BuildP2WPKH(u UTXO, pay Payment, net *chaincfg.Params) (*wire.MsgTx, []byte, error) {
	if len(u.PkHash) != 20 || len(pay.ToPkHash) != 20 || len(pay.ChangePk) != 20 {
		return nil, nil, errors.New("pkhash must be 20 bytes")
	}
	if pay.Amount+pay.Fee > u.Amount {
		return nil, nil, errors.New("insufficient funds")
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	// Input
	h, err := chainhashFromStr(u.TxID)
	if err != nil {
		return nil, nil, err
	}
	txIn := wire.NewTxIn(wire.NewOutPoint(h, u.Vout), nil, nil)
	tx.AddTxIn(txIn)
	// Outputs
	pkScriptPay, err := txscript.PayToAddrScript(addrFromPkHash(pay.ToPkHash, net))
	if err != nil {
		return nil, nil, err
	}
	tx.AddTxOut(wire.NewTxOut(pay.Amount, pkScriptPay))
	change := u.Amount - pay.Amount - pay.Fee
	if change > 0 {
		pkScriptChange, err := txscript.PayToAddrScript(addrFromPkHash(pay.ChangePk, net))
		if err != nil {
			return nil, nil, err
		}
		tx.AddTxOut(wire.NewTxOut(change, pkScriptChange))
	}
	// BIP143: the sighash commits to the output being spent (the input's own
	// P2WPKH script, from which the P2PKH scriptCode is derived) and its
	// amount, not to any of the new outputs.
	prevPkScript, err := txscript.PayToAddrScript(addrFromPkHash(u.PkHash, net))
	if err != nil {
		return nil, nil, err
	}
	fetcher := txscript.NewCannedPrevOutputFetcher(prevPkScript, u.Amount)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	sighash, err := txscript.CalcWitnessSigHash(prevPkScript, sigHashes, txscript.SigHashAll, tx, 0, u.Amount)
	if err != nil {
		return nil, nil, err
	}
	return tx, sighash, nil
}

// AttachSignature sets the witness for input 0 with DER signature+hashType and compressed pubkey.
func AttachSignature(tx *wire.MsgTx, derSig []byte, hashType txscript.SigHashType, compressedPub []byte) {
	sigWithHashType := append(append([]byte(nil), derSig...), byte(hashType))
	tx.TxIn[0].Witness = wire.TxWitness{sigWithHashType, compressedPub}
}

// Helper: decode txid big-endian to chainhash.
func chainhashFromStr(s string) (*chainhash.Hash, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("txid must be 32 bytes hex")
	}
	b = reverseBytes(b)
	var h chainhash.Hash
	copy(h[:], b)
	return &h, nil
}

func reverseBytes(b []byte) []byte {
	n := len(b)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = b[n-1-i]
	}
	return out
}

func addrFromPkHash(pk []byte, net *chaincfg.Params) *btcutil.AddressWitnessPubKeyHash {
	addr, _ := btcutil.NewAddressWitnessPubKeyHash(pk, net)
	return addr
}

// Hash160Compressed returns hash160 of a compressed secp256k1 pubkey.
func Hash160Compressed(compressedPub []byte) ([]byte, error) {
	if len(compressedPub) != 33 {
		return nil, errors.New("compressed pubkey must be 33 bytes")
	}
	h := btcutil.Hash160(compressedPub)
	return h, nil
}

// DeriveP2WPKHAddress creates a P2WPKH (witness pubkey hash) address from a compressed pubkey.
func DeriveP2WPKHAddress(compressedPub []byte, net *chaincfg.Params) (btcutil.Address, error) {
	pkHash, err := Hash160Compressed(compressedPub)
	if err != nil {
		return nil, err
	}
	return btcutil.NewAddressWitnessPubKeyHash(pkHash, net)
}

// DeriveP2PKHAddress creates a legacy P2PKH (pay to pubkey hash) address from a compressed pubkey.
func DeriveP2PKHAddress(compressedPub []byte, net *chaincfg.Params) (btcutil.Address, error) {
	pkHash, err := Hash160Compressed(compressedPub)
	if err != nil {
		return nil, err
	}
	return btcutil.NewAddressPubKeyHash(pkHash, net)
}

// DeriveP2SHAddress creates a P2SH (pay to script hash) address from a redeem script.
func DeriveP2SHAddress(redeemScript []byte, net *chaincfg.Params) (btcutil.Address, error) {
	scriptHash := btcutil.Hash160(redeemScript)
	return btcutil.NewAddressScriptHash(scriptHash, net)
}

// BuildP2PKH creates a legacy P2PKH transaction (pay to pubkey hash) and returns the sighash.
func BuildP2PKH(u UTXO, pay Payment, net *chaincfg.Params) (*wire.MsgTx, []byte, error) {
	if len(u.PkHash) != 20 || len(pay.ToPkHash) != 20 || len(pay.ChangePk) != 20 {
		return nil, nil, errors.New("pkhash must be 20 bytes")
	}
	if pay.Amount+pay.Fee > u.Amount {
		return nil, nil, errors.New("insufficient funds")
	}

	tx := wire.NewMsgTx(wire.TxVersion)

	// Input
	h, err := chainhashFromStr(u.TxID)
	if err != nil {
		return nil, nil, err
	}
	txIn := wire.NewTxIn(wire.NewOutPoint(h, u.Vout), nil, nil)
	tx.AddTxIn(txIn)

	// Output to recipient
	payAddr, err := btcutil.NewAddressPubKeyHash(pay.ToPkHash, net)
	if err != nil {
		return nil, nil, err
	}
	pkScriptPay, err := txscript.PayToAddrScript(payAddr)
	if err != nil {
		return nil, nil, err
	}
	tx.AddTxOut(wire.NewTxOut(pay.Amount, pkScriptPay))

	// Change output
	change := u.Amount - pay.Amount - pay.Fee
	if change > 0 {
		changeAddr, err := btcutil.NewAddressPubKeyHash(pay.ChangePk, net)
		if err != nil {
			return nil, nil, err
		}
		pkScriptChange, err := txscript.PayToAddrScript(changeAddr)
		if err != nil {
			return nil, nil, err
		}
		tx.AddTxOut(wire.NewTxOut(change, pkScriptChange))
	}

	// Create input script for signing
	inputAddr, err := btcutil.NewAddressPubKeyHash(u.PkHash, net)
	if err != nil {
		return nil, nil, err
	}
	inputScript, err := txscript.PayToAddrScript(inputAddr)
	if err != nil {
		return nil, nil, err
	}

	// Calculate signature hash for legacy P2PKH
	sighash, err := txscript.CalcSignatureHash(inputScript, txscript.SigHashAll, tx, 0)
	if err != nil {
		return nil, nil, err
	}

	return tx, sighash, nil
}

// AttachP2PKHSignature attaches a DER signature to a legacy P2PKH transaction.
func AttachP2PKHSignature(tx *wire.MsgTx, derSig []byte, hashType txscript.SigHashType, compressedPub []byte) error {
	sigWithHashType := append(append([]byte(nil), derSig...), byte(hashType))

	// P2PKH scriptSig: <signature> <pubkey>
	builder := txscript.NewScriptBuilder()
	builder.AddData(sigWithHashType)
	builder.AddData(compressedPub)
	scriptSig, err := builder.Script()
	if err != nil {
		return err
	}

	tx.TxIn[0].SignatureScript = scriptSig
	return nil
}
