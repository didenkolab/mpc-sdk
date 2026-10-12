package litecoin

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil/bech32"
)

// Litecoin network parameters
var (
	// Litecoin Mainnet parameters
	LitecoinMainNetParams = chaincfg.Params{
		Name:        "mainnet",
		Net:         0xdbb6c0fb, // Litecoin mainnet magic number
		DefaultPort: "9333",
		DNSSeeds: []chaincfg.DNSSeed{
			{Host: "seed-a.litecoin.loshan.co.uk", HasFiltering: true},
			{Host: "dnsseed.thrasher.io", HasFiltering: true},
			{Host: "dnsseed.litecointools.com", HasFiltering: false},
		},

		// Human-readable part for Bech32 encoded segwit addresses
		Bech32HRPSegwit: "ltc",

		// Address encoding magics
		PubKeyHashAddrID:        0x30, // starts with L
		ScriptHashAddrID:        0x32, // starts with M (P2SH)
		PrivateKeyID:            0xB0, // starts with 6 (WIF)
		WitnessPubKeyHashAddrID: 0x06, // starts with p2wpkh
		WitnessScriptHashAddrID: 0x0A, // starts with p2wsh

		// BIP32 hierarchical deterministic extended key magics
		HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with Ltpv
		HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with Ltub

		// BIP44 coin type used in the hierarchical deterministic path
		HDCoinType: 2,
	}

	// Litecoin Testnet parameters
	LitecoinTestNetParams = chaincfg.Params{
		Name:        "testnet",
		Net:         0xf1c8d2fd, // Litecoin testnet magic number
		DefaultPort: "19333",

		// Human-readable part for Bech32 encoded segwit addresses
		Bech32HRPSegwit: "tltc",

		// Address encoding magics
		PubKeyHashAddrID:        0x6f, // starts with m or n
		ScriptHashAddrID:        0x3a, // starts with Q (P2SH)
		PrivateKeyID:            0xef, // starts with 9 or c (WIF)
		WitnessPubKeyHashAddrID: 0x03,
		WitnessScriptHashAddrID: 0x28,

		// BIP32 hierarchical deterministic extended key magics
		HDPrivateKeyID: [4]byte{0x04, 0x35, 0x83, 0x94}, // starts with ttpv
		HDPublicKeyID:  [4]byte{0x04, 0x35, 0x87, 0xcf}, // starts with ttub

		// BIP44 coin type used in the hierarchical deterministic path
		HDCoinType: 1,
	}
)

// UTXO represents an unspent transaction output for Litecoin
type UTXO struct {
	TxID   string // Transaction ID hex string
	Vout   uint32 // Output index
	Amount int64  // Amount in litoshis (1 LTC = 100,000,000 litoshis)
	PkHash []byte // Public key hash (20 bytes)
}

// Payment represents payment details for Litecoin transaction
type Payment struct {
	ToPkHash []byte // Recipient public key hash (20 bytes)
	Amount   int64  // Amount to send in litoshis
	ChangePk []byte // Change address public key hash (20 bytes)
	Fee      int64  // Transaction fee in litoshis
}

// DeriveP2PKHAddress creates a legacy P2PKH Litecoin address from compressed public key.
// Litecoin P2PKH addresses start with 'L' on mainnet and 'm'/'n' on testnet.
func DeriveP2PKHAddress(compressedPub []byte, net *chaincfg.Params) (btcutil.Address, error) {
	if len(compressedPub) != 33 {
		return nil, errors.New("compressed pubkey must be 33 bytes")
	}

	// Hash160 = RIPEMD160(SHA256(pubkey))
	pkHash, err := Hash160Compressed(compressedPub)
	if err != nil {
		return nil, fmt.Errorf("hash160: %w", err)
	}

	// Create P2PKH address
	addr, err := btcutil.NewAddressPubKeyHash(pkHash, net)
	if err != nil {
		return nil, fmt.Errorf("create P2PKH address: %w", err)
	}

	return addr, nil
}

// DeriveP2WPKHAddress creates a SegWit P2WPKH Litecoin address from compressed public key.
// Litecoin SegWit addresses start with 'ltc1' on mainnet and 'tltc1' on testnet.
func DeriveP2WPKHAddress(compressedPub []byte, net *chaincfg.Params) (btcutil.Address, error) {
	if len(compressedPub) != 33 {
		return nil, errors.New("compressed pubkey must be 33 bytes")
	}

	// Hash160 for SegWit
	pkHash, err := Hash160Compressed(compressedPub)
	if err != nil {
		return nil, fmt.Errorf("hash160: %w", err)
	}

	// Create P2WPKH address
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, net)
	if err != nil {
		return nil, fmt.Errorf("create P2WPKH address: %w", err)
	}

	return addr, nil
}

// DeriveP2SHAddress creates a P2SH Litecoin address from redeem script.
// Litecoin P2SH addresses start with 'M' on mainnet and 'Q' on testnet.
func DeriveP2SHAddress(redeemScript []byte, net *chaincfg.Params) (btcutil.Address, error) {
	if len(redeemScript) == 0 {
		return nil, errors.New("redeem script cannot be empty")
	}

	// Hash160 of the redeem script
	scriptHashBytes := btcutil.Hash160(redeemScript)

	// Create P2SH address
	addr, err := btcutil.NewAddressScriptHash(scriptHashBytes, net)
	if err != nil {
		return nil, fmt.Errorf("create P2SH address: %w", err)
	}

	return addr, nil
}

// BuildP2PKH creates a legacy P2PKH Litecoin transaction and returns sighash for signing.
func BuildP2PKH(u UTXO, pay Payment, net *chaincfg.Params) (*wire.MsgTx, []byte, error) {
	// Input validation
	if pay.Amount+pay.Fee > u.Amount {
		return nil, nil, errors.New("insufficient funds")
	}
	if len(u.PkHash) != 20 {
		return nil, nil, errors.New("invalid input pubkey hash length")
	}
	if len(pay.ToPkHash) != 20 {
		return nil, nil, errors.New("invalid output pubkey hash length")
	}

	// Parse input transaction hash
	txHash, err := chainhash.NewHashFromStr(u.TxID)
	if err != nil {
		return nil, nil, fmt.Errorf("parse txid: %w", err)
	}

	// Create transaction
	tx := wire.NewMsgTx(wire.TxVersion)

	// Add input
	outPoint := wire.NewOutPoint(txHash, u.Vout)
	txIn := wire.NewTxIn(outPoint, nil, nil)
	tx.AddTxIn(txIn)

	// Add output to recipient
	recipientScript, err := createP2PKHScript(pay.ToPkHash)
	if err != nil {
		return nil, nil, fmt.Errorf("create recipient script: %w", err)
	}
	recipientOut := wire.NewTxOut(pay.Amount, recipientScript)
	tx.AddTxOut(recipientOut)

	// Add change output if needed
	changeAmount := u.Amount - pay.Amount - pay.Fee
	if changeAmount > 0 {
		if len(pay.ChangePk) != 20 {
			return nil, nil, errors.New("invalid change pubkey hash length")
		}
		changeScript, err := createP2PKHScript(pay.ChangePk)
		if err != nil {
			return nil, nil, fmt.Errorf("create change script: %w", err)
		}
		changeOut := wire.NewTxOut(changeAmount, changeScript)
		tx.AddTxOut(changeOut)
	}

	// Create signature script for input
	inputScript, err := createP2PKHScript(u.PkHash)
	if err != nil {
		return nil, nil, fmt.Errorf("create input script: %w", err)
	}

	// Calculate sighash for signing
	sighash, err := txscript.CalcSignatureHash(inputScript, txscript.SigHashAll, tx, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("calc sighash: %w", err)
	}

	return tx, sighash, nil
}

// BuildP2WPKH creates a SegWit P2WPKH Litecoin transaction and returns sighash for signing.
func BuildP2WPKH(u UTXO, pay Payment, net *chaincfg.Params) (*wire.MsgTx, []byte, error) {
	// Input validation
	if pay.Amount+pay.Fee > u.Amount {
		return nil, nil, errors.New("insufficient funds")
	}
	if len(u.PkHash) != 20 {
		return nil, nil, errors.New("invalid input pubkey hash length")
	}
	if len(pay.ToPkHash) != 20 {
		return nil, nil, errors.New("invalid output pubkey hash length")
	}

	// Parse input transaction hash
	txHash, err := chainhash.NewHashFromStr(u.TxID)
	if err != nil {
		return nil, nil, fmt.Errorf("parse txid: %w", err)
	}

	// Create transaction
	tx := wire.NewMsgTx(wire.TxVersion)

	// Add input with empty script (SegWit)
	outPoint := wire.NewOutPoint(txHash, u.Vout)
	txIn := wire.NewTxIn(outPoint, nil, nil)
	tx.AddTxIn(txIn)

	// Add output to recipient
	recipientScript, err := createP2WPKHScript(pay.ToPkHash)
	if err != nil {
		return nil, nil, fmt.Errorf("create recipient script: %w", err)
	}
	recipientOut := wire.NewTxOut(pay.Amount, recipientScript)
	tx.AddTxOut(recipientOut)

	// Add change output if needed
	changeAmount := u.Amount - pay.Amount - pay.Fee
	if changeAmount > 0 {
		if len(pay.ChangePk) != 20 {
			return nil, nil, errors.New("invalid change pubkey hash length")
		}
		changeScript, err := createP2WPKHScript(pay.ChangePk)
		if err != nil {
			return nil, nil, fmt.Errorf("create change script: %w", err)
		}
		changeOut := wire.NewTxOut(changeAmount, changeScript)
		tx.AddTxOut(changeOut)
	}

	// Create witness script for SegWit signing
	witnessScript, err := createP2PKHScript(u.PkHash) // P2PKH script used for witness
	if err != nil {
		return nil, nil, fmt.Errorf("create witness script: %w", err)
	}

	// segwit v0: scriptCode = P2PKH template, amount = input amount. The
	// prevout fetcher describes the output being spent, not the recipient.
	prevScript, err := createP2WPKHScript(u.PkHash)
	if err != nil {
		return nil, nil, fmt.Errorf("create prevout script: %w", err)
	}
	prevFetcher := txscript.NewCannedPrevOutputFetcher(prevScript, u.Amount)
	sigHashes := txscript.NewTxSigHashes(tx, prevFetcher)
	sighash, err := txscript.CalcWitnessSigHash(
		witnessScript,
		sigHashes,
		txscript.SigHashAll,
		tx,
		0,
		u.Amount,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("calc witness sighash: %w", err)
	}

	return tx, sighash[:], nil
}

// AttachP2PKHSignature attaches signature to P2PKH Litecoin transaction.
func AttachP2PKHSignature(tx *wire.MsgTx, derSig []byte, hashType txscript.SigHashType, compressedPub []byte) error {
	if len(derSig) == 0 {
		return errors.New("signature cannot be empty")
	}
	if len(compressedPub) != 33 {
		return errors.New("compressed pubkey must be 33 bytes")
	}

	// Build signature script: <signature> <pubkey>
	sigBuilder := txscript.NewScriptBuilder()
	sigBuilder.AddData(append(append([]byte(nil), derSig...), byte(hashType)))
	sigBuilder.AddData(compressedPub)

	sigScript, err := sigBuilder.Script()
	if err != nil {
		return fmt.Errorf("build signature script: %w", err)
	}

	// Attach to first input
	if len(tx.TxIn) == 0 {
		return errors.New("transaction has no inputs")
	}
	tx.TxIn[0].SignatureScript = sigScript

	return nil
}

// AttachP2WPKHSignature attaches signature to P2WPKH Litecoin transaction.
func AttachP2WPKHSignature(tx *wire.MsgTx, derSig []byte, hashType txscript.SigHashType, compressedPub []byte) error {
	if len(derSig) == 0 {
		return errors.New("signature cannot be empty")
	}
	if len(compressedPub) != 33 {
		return errors.New("compressed pubkey must be 33 bytes")
	}

	// Build witness: [signature, pubkey]
	witness := wire.TxWitness{
		append(append([]byte(nil), derSig...), byte(hashType)),
		compressedPub,
	}

	// Attach to first input
	if len(tx.TxIn) == 0 {
		return errors.New("transaction has no inputs")
	}
	tx.TxIn[0].Witness = witness

	return nil
}

// Hash160Compressed returns RIPEMD160(SHA256(compressedPubkey))
func Hash160Compressed(compressedPub []byte) ([]byte, error) {
	if len(compressedPub) != 33 {
		return nil, errors.New("compressed pubkey must be 33 bytes")
	}

	return btcutil.Hash160(compressedPub), nil
}

// ConvertLTCToLitoshi converts LTC to litoshis (1 LTC = 100,000,000 litoshis)
func ConvertLTCToLitoshi(ltc float64) int64 {
	return int64(ltc * 100000000)
}

// ConvertLitoshiToLTC converts litoshis to LTC
func ConvertLitoshiToLTC(litoshi int64) float64 {
	return float64(litoshi) / 100000000
}

// GetMainnetParams returns Litecoin mainnet parameters
func GetMainnetParams() *chaincfg.Params {
	return &LitecoinMainNetParams
}

// GetTestnetParams returns Litecoin testnet parameters
func GetTestnetParams() *chaincfg.Params {
	return &LitecoinTestNetParams
}

// ValidateAddress validates a Litecoin address string
func ValidateAddress(address string, net *chaincfg.Params) (btcutil.Address, error) {
	addr, err := btcutil.DecodeAddress(address, net)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}

	if !addr.IsForNet(net) {
		return nil, errors.New("address is not for the specified network")
	}

	return addr, nil
}

// CreateBech32Address creates a Bech32 encoded Litecoin address
func CreateBech32Address(witnessProg []byte, net *chaincfg.Params) (string, error) {
	if len(witnessProg) != 20 && len(witnessProg) != 32 {
		return "", errors.New("witness program must be 20 or 32 bytes")
	}

	// Witness version 0 covers both P2WPKH (20 bytes) and P2WSH (32 bytes).
	const witnessVersion byte = 0

	converted, err := bech32.ConvertBits(witnessProg, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("convert bits: %w", err)
	}

	// Prepend witness version
	data := append([]byte{witnessVersion}, converted...)

	address, err := bech32.Encode(net.Bech32HRPSegwit, data)
	if err != nil {
		return "", fmt.Errorf("encode bech32: %w", err)
	}

	return address, nil
}

// Helper functions

// createP2PKHScript creates a P2PKH script for the given public key hash
func createP2PKHScript(pkHash []byte) ([]byte, error) {
	if len(pkHash) != 20 {
		return nil, errors.New("public key hash must be 20 bytes")
	}

	// OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_DUP)
	builder.AddOp(txscript.OP_HASH160)
	builder.AddData(pkHash)
	builder.AddOp(txscript.OP_EQUALVERIFY)
	builder.AddOp(txscript.OP_CHECKSIG)

	return builder.Script()
}

// createP2WPKHScript creates a P2WPKH script for the given public key hash
func createP2WPKHScript(pkHash []byte) ([]byte, error) {
	if len(pkHash) != 20 {
		return nil, errors.New("public key hash must be 20 bytes")
	}

	// OP_0 <20-byte-pubkey-hash>
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0)
	builder.AddData(pkHash)

	return builder.Script()
}
