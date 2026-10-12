package mpcdemo

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// DERSignature converts a 64-byte r||s signature to strict DER with a low S
// value, as required for Bitcoin-style transactions.
func DERSignature(sig []byte) ([]byte, error) {
	parsed, err := ParseRS(sig)
	if err != nil {
		return nil, err
	}
	return parsed.Serialize(), nil
}

// VerifyInput executes the scripts of input 0 of a signed transaction with the
// btcd script engine, exactly as a node validates it. prevScript and amount
// describe the output being spent.
func VerifyInput(tx *wire.MsgTx, prevScript []byte, amount int64) error {
	fetcher := txscript.NewCannedPrevOutputFetcher(prevScript, amount)
	engine, err := txscript.NewEngine(prevScript, tx, 0, txscript.StandardVerifyFlags,
		nil, txscript.NewTxSigHashes(tx, fetcher), amount, fetcher)
	if err != nil {
		return fmt.Errorf("script engine: %w", err)
	}
	if err := engine.Execute(); err != nil {
		return fmt.Errorf("script verification: %w", err)
	}
	return nil
}

// SerializeTx returns the wire encoding of a transaction (with witness data).
func SerializeTx(tx *wire.MsgTx) ([]byte, error) {
	var buf bytes.Buffer
	if err := tx.Serialize(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
