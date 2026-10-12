package litecoin

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/txscript"
)

func TestDeriveP2PKHAddress(t *testing.T) {
	// Sample compressed pubkey from MPC (33 bytes)
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	// Test mainnet address
	addr, err := DeriveP2PKHAddress(pubBytes, GetMainnetParams())
	if err != nil {
		t.Fatalf("derive P2PKH mainnet address: %v", err)
	}

	addrStr := addr.EncodeAddress()
	if !strings.HasPrefix(addrStr, "L") {
		t.Fatalf("mainnet P2PKH address should start with 'L', got: %s", addrStr)
	}

	// Test testnet address
	testnetAddr, err := DeriveP2PKHAddress(pubBytes, GetTestnetParams())
	if err != nil {
		t.Fatalf("derive P2PKH testnet address: %v", err)
	}

	testnetAddrStr := testnetAddr.EncodeAddress()
	if !strings.HasPrefix(testnetAddrStr, "m") && !strings.HasPrefix(testnetAddrStr, "n") {
		t.Fatalf("testnet P2PKH address should start with 'm' or 'n', got: %s", testnetAddrStr)
	}

	// Test with invalid public key
	_, err = DeriveP2PKHAddress([]byte{0x01, 0x02}, GetMainnetParams())
	if err == nil {
		t.Fatalf("expected error for invalid pubkey length")
	}
}

func TestDeriveP2WPKHAddress(t *testing.T) {
	// Sample compressed pubkey from MPC
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	// Test mainnet SegWit address
	addr, err := DeriveP2WPKHAddress(pubBytes, GetMainnetParams())
	if err != nil {
		t.Fatalf("derive P2WPKH mainnet address: %v", err)
	}

	addrStr := addr.EncodeAddress()
	if !strings.HasPrefix(addrStr, "ltc1") {
		t.Fatalf("mainnet P2WPKH address should start with 'ltc1', got: %s", addrStr)
	}

	// Test testnet SegWit address
	testnetAddr, err := DeriveP2WPKHAddress(pubBytes, GetTestnetParams())
	if err != nil {
		t.Fatalf("derive P2WPKH testnet address: %v", err)
	}

	testnetAddrStr := testnetAddr.EncodeAddress()
	if !strings.HasPrefix(testnetAddrStr, "tltc1") {
		t.Fatalf("testnet P2WPKH address should start with 'tltc1', got: %s", testnetAddrStr)
	}

	// Test with invalid public key
	_, err = DeriveP2WPKHAddress([]byte{0x01, 0x02}, GetMainnetParams())
	if err == nil {
		t.Fatalf("expected error for invalid pubkey length")
	}
}

func TestDeriveP2SHAddress(t *testing.T) {
	// Sample redeem script (P2WPKH wrapped in P2SH)
	redeemScript, _ := hex.DecodeString("0014" + "89abcdefabbaabbaabbaabbaabbaabbaabbaabba")

	// Test mainnet P2SH address
	addr, err := DeriveP2SHAddress(redeemScript, GetMainnetParams())
	if err != nil {
		t.Fatalf("derive P2SH mainnet address: %v", err)
	}

	addrStr := addr.EncodeAddress()
	if !strings.HasPrefix(addrStr, "M") {
		t.Fatalf("mainnet P2SH address should start with 'M', got: %s", addrStr)
	}

	// Test testnet P2SH address
	testnetAddr, err := DeriveP2SHAddress(redeemScript, GetTestnetParams())
	if err != nil {
		t.Fatalf("derive P2SH testnet address: %v", err)
	}

	testnetAddrStr := testnetAddr.EncodeAddress()
	if !strings.HasPrefix(testnetAddrStr, "Q") && !strings.HasPrefix(testnetAddrStr, "2") {
		t.Fatalf("testnet P2SH address should start with 'Q' or '2', got: %s", testnetAddrStr)
	}

	// Test with empty redeem script
	_, err = DeriveP2SHAddress([]byte{}, GetMainnetParams())
	if err == nil {
		t.Fatalf("expected error for empty redeem script")
	}
}

func TestBuildP2PKH(t *testing.T) {
	// Sample UTXO with MPC-derived address
	utxo := UTXO{
		TxID:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		Vout:   0,
		Amount: ConvertLTCToLitoshi(1.0), // 1 LTC
		PkHash: make([]byte, 20),
	}
	// Fill with sample hash
	for i := range utxo.PkHash {
		utxo.PkHash[i] = byte(i)
	}

	payment := Payment{
		ToPkHash: make([]byte, 20),
		Amount:   ConvertLTCToLitoshi(0.5), // 0.5 LTC
		ChangePk: make([]byte, 20),
		Fee:      ConvertLTCToLitoshi(0.001), // 0.001 LTC fee
	}
	// Fill recipient and change hashes
	for i := range payment.ToPkHash {
		payment.ToPkHash[i] = byte(i + 100)
		payment.ChangePk[i] = byte(i + 200)
	}

	tx, sighash, err := BuildP2PKH(utxo, payment, GetMainnetParams())
	if err != nil {
		t.Fatalf("build P2PKH transaction: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(sighash) != 32 {
		t.Fatalf("expected 32-byte sighash, got %d", len(sighash))
	}

	// Verify transaction structure
	if len(tx.TxIn) != 1 {
		t.Fatalf("expected 1 input, got %d", len(tx.TxIn))
	}

	if len(tx.TxOut) != 2 { // output + change
		t.Fatalf("expected 2 outputs (payment + change), got %d", len(tx.TxOut))
	}

	// Verify output amount
	if tx.TxOut[0].Value != payment.Amount {
		t.Fatalf("output amount mismatch: got %d, expected %d", tx.TxOut[0].Value, payment.Amount)
	}

	// Verify change amount
	expectedChange := utxo.Amount - payment.Amount - payment.Fee
	if tx.TxOut[1].Value != expectedChange {
		t.Fatalf("change amount mismatch: got %d, expected %d", tx.TxOut[1].Value, expectedChange)
	}

	// Test insufficient funds
	payment.Amount = ConvertLTCToLitoshi(2.0) // More than UTXO
	_, _, err = BuildP2PKH(utxo, payment, GetMainnetParams())
	if err == nil {
		t.Fatalf("expected error for insufficient funds")
	}
}

func TestBuildP2WPKH(t *testing.T) {
	// Sample UTXO
	utxo := UTXO{
		TxID:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		Vout:   1,
		Amount: ConvertLTCToLitoshi(2.0), // 2 LTC
		PkHash: make([]byte, 20),
	}
	for i := range utxo.PkHash {
		utxo.PkHash[i] = byte(i + 10)
	}

	payment := Payment{
		ToPkHash: make([]byte, 20),
		Amount:   ConvertLTCToLitoshi(1.5), // 1.5 LTC
		ChangePk: make([]byte, 20),
		Fee:      ConvertLTCToLitoshi(0.0001), // 0.0001 LTC fee
	}
	for i := range payment.ToPkHash {
		payment.ToPkHash[i] = byte(i + 110)
		payment.ChangePk[i] = byte(i + 210)
	}

	tx, sighash, err := BuildP2WPKH(utxo, payment, GetMainnetParams())
	if err != nil {
		t.Fatalf("build P2WPKH transaction: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(sighash) != 32 {
		t.Fatalf("expected 32-byte sighash, got %d", len(sighash))
	}

	// Verify transaction structure
	if len(tx.TxIn) != 1 {
		t.Fatalf("expected 1 input, got %d", len(tx.TxIn))
	}

	if len(tx.TxOut) != 2 { // output + change
		t.Fatalf("expected 2 outputs, got %d", len(tx.TxOut))
	}

	// Verify input has empty signature script (SegWit)
	if len(tx.TxIn[0].SignatureScript) != 0 {
		t.Fatalf("SegWit input should have empty signature script, got %d bytes", len(tx.TxIn[0].SignatureScript))
	}
}

func TestAttachP2PKHSignature(t *testing.T) {
	// Create test transaction
	utxo := UTXO{
		TxID:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		Vout:   0,
		Amount: ConvertLTCToLitoshi(1.0),
		PkHash: make([]byte, 20),
	}

	payment := Payment{
		ToPkHash: make([]byte, 20),
		Amount:   ConvertLTCToLitoshi(0.9),
		ChangePk: make([]byte, 20),
		Fee:      ConvertLTCToLitoshi(0.1),
	}

	tx, _, err := BuildP2PKH(utxo, payment, GetMainnetParams())
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}

	// Create dummy signature and pubkey
	derSig := make([]byte, 71) // Typical DER signature size
	for i := range derSig {
		derSig[i] = byte(i % 256)
	}

	compressedPub := make([]byte, 33)
	compressedPub[0] = 0x02 // Compressed pubkey prefix
	for i := 1; i < 33; i++ {
		compressedPub[i] = byte(i)
	}

	err = AttachP2PKHSignature(tx, derSig, txscript.SigHashAll, compressedPub)
	if err != nil {
		t.Fatalf("attach P2PKH signature: %v", err)
	}

	// Verify signature script is not empty
	if len(tx.TxIn[0].SignatureScript) == 0 {
		t.Fatalf("signature script should not be empty after attaching signature")
	}

	// Test with invalid parameters
	err = AttachP2PKHSignature(tx, []byte{}, txscript.SigHashAll, compressedPub)
	if err == nil {
		t.Fatalf("expected error for empty signature")
	}

	err = AttachP2PKHSignature(tx, derSig, txscript.SigHashAll, []byte{0x01})
	if err == nil {
		t.Fatalf("expected error for invalid pubkey length")
	}
}

func TestAttachP2WPKHSignature(t *testing.T) {
	// Create test SegWit transaction
	utxo := UTXO{
		TxID:   "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		Vout:   0,
		Amount: ConvertLTCToLitoshi(1.0),
		PkHash: make([]byte, 20),
	}

	payment := Payment{
		ToPkHash: make([]byte, 20),
		Amount:   ConvertLTCToLitoshi(0.9),
		ChangePk: make([]byte, 20),
		Fee:      ConvertLTCToLitoshi(0.1),
	}

	tx, _, err := BuildP2WPKH(utxo, payment, GetMainnetParams())
	if err != nil {
		t.Fatalf("build SegWit transaction: %v", err)
	}

	// Create dummy signature and pubkey
	derSig := make([]byte, 71)
	for i := range derSig {
		derSig[i] = byte(i % 256)
	}

	compressedPub := make([]byte, 33)
	compressedPub[0] = 0x03 // Compressed pubkey prefix
	for i := 1; i < 33; i++ {
		compressedPub[i] = byte(i + 100)
	}

	err = AttachP2WPKHSignature(tx, derSig, txscript.SigHashAll, compressedPub)
	if err != nil {
		t.Fatalf("attach P2WPKH signature: %v", err)
	}

	// Verify witness is attached
	if len(tx.TxIn[0].Witness) != 2 {
		t.Fatalf("witness should have 2 elements (signature + pubkey), got %d", len(tx.TxIn[0].Witness))
	}

	// Verify signature script is still empty (SegWit)
	if len(tx.TxIn[0].SignatureScript) != 0 {
		t.Fatalf("SegWit signature script should be empty, got %d bytes", len(tx.TxIn[0].SignatureScript))
	}

	// Test with invalid parameters
	err = AttachP2WPKHSignature(tx, []byte{}, txscript.SigHashAll, compressedPub)
	if err == nil {
		t.Fatalf("expected error for empty signature")
	}
}

func TestHash160Compressed(t *testing.T) {
	// Test with valid compressed pubkey
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	hash160, err := Hash160Compressed(pubBytes)
	if err != nil {
		t.Fatalf("hash160 error: %v", err)
	}

	if len(hash160) != 20 {
		t.Fatalf("hash160 should be 20 bytes, got %d", len(hash160))
	}

	// Test deterministic output
	hash160_2, err := Hash160Compressed(pubBytes)
	if err != nil {
		t.Fatalf("second hash160 error: %v", err)
	}

	if hex.EncodeToString(hash160) != hex.EncodeToString(hash160_2) {
		t.Fatalf("hash160 not deterministic")
	}

	// Test with invalid length
	_, err = Hash160Compressed([]byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid pubkey length")
	}
}

func TestConvertLTCToLitoshi(t *testing.T) {
	// Test 1 LTC = 100,000,000 litoshis
	litoshis := ConvertLTCToLitoshi(1.0)
	if litoshis != 100000000 {
		t.Fatalf("1 LTC should be 100000000 litoshis, got %d", litoshis)
	}

	// Test 0.5 LTC
	litoshis = ConvertLTCToLitoshi(0.5)
	if litoshis != 50000000 {
		t.Fatalf("0.5 LTC should be 50000000 litoshis, got %d", litoshis)
	}

	// Test small amount
	litoshis = ConvertLTCToLitoshi(0.00000001)
	if litoshis != 1 {
		t.Fatalf("0.00000001 LTC should be 1 litoshi, got %d", litoshis)
	}
}

func TestConvertLitoshiToLTC(t *testing.T) {
	// Test 100,000,000 litoshis = 1 LTC
	ltc := ConvertLitoshiToLTC(100000000)
	if ltc != 1.0 {
		t.Fatalf("100000000 litoshis should be 1.0 LTC, got %f", ltc)
	}

	// Test round trip conversion
	originalLTC := 2.5
	litoshis := ConvertLTCToLitoshi(originalLTC)
	backToLTC := ConvertLitoshiToLTC(litoshis)

	if backToLTC != originalLTC {
		t.Fatalf("round trip conversion failed: original %f, back %f", originalLTC, backToLTC)
	}
}

func TestGetNetworkParams(t *testing.T) {
	mainnet := GetMainnetParams()
	if mainnet.Name != "mainnet" {
		t.Fatalf("mainnet name should be 'mainnet', got %s", mainnet.Name)
	}

	if mainnet.Bech32HRPSegwit != "ltc" {
		t.Fatalf("mainnet Bech32 HRP should be 'ltc', got %s", mainnet.Bech32HRPSegwit)
	}

	if mainnet.HDCoinType != 2 {
		t.Fatalf("mainnet HD coin type should be 2, got %d", mainnet.HDCoinType)
	}

	testnet := GetTestnetParams()
	if testnet.Name != "testnet" {
		t.Fatalf("testnet name should be 'testnet', got %s", testnet.Name)
	}

	if testnet.Bech32HRPSegwit != "tltc" {
		t.Fatalf("testnet Bech32 HRP should be 'tltc', got %s", testnet.Bech32HRPSegwit)
	}

	if testnet.HDCoinType != 1 {
		t.Fatalf("testnet HD coin type should be 1, got %d", testnet.HDCoinType)
	}
}

func TestValidateAddress(t *testing.T) {
	// Create a valid mainnet address first
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	addr, err := DeriveP2PKHAddress(pubBytes, GetMainnetParams())
	if err != nil {
		t.Fatalf("derive address: %v", err)
	}

	// Test validation of valid address
	validatedAddr, err := ValidateAddress(addr.EncodeAddress(), GetMainnetParams())
	if err != nil {
		t.Fatalf("validate valid address: %v", err)
	}

	if validatedAddr.EncodeAddress() != addr.EncodeAddress() {
		t.Fatalf("validated address mismatch")
	}

	// Test invalid address string
	_, err = ValidateAddress("invalid_address", GetMainnetParams())
	if err == nil {
		t.Fatalf("expected error for invalid address")
	}

	// Test wrong network validation
	_, err = ValidateAddress(addr.EncodeAddress(), GetTestnetParams())
	if err == nil {
		t.Fatalf("expected error for wrong network")
	}
}

func TestCreateBech32Address(t *testing.T) {
	// Test P2WPKH (20 bytes)
	witnessProg := make([]byte, 20)
	for i := range witnessProg {
		witnessProg[i] = byte(i)
	}

	// Test mainnet Bech32
	addr, err := CreateBech32Address(witnessProg, GetMainnetParams())
	if err != nil {
		t.Fatalf("create mainnet Bech32 address: %v", err)
	}

	if !strings.HasPrefix(addr, "ltc1") {
		t.Fatalf("mainnet Bech32 address should start with 'ltc1', got: %s", addr)
	}

	// Test testnet Bech32
	testnetAddr, err := CreateBech32Address(witnessProg, GetTestnetParams())
	if err != nil {
		t.Fatalf("create testnet Bech32 address: %v", err)
	}

	if !strings.HasPrefix(testnetAddr, "tltc1") {
		t.Fatalf("testnet Bech32 address should start with 'tltc1', got: %s", testnetAddr)
	}

	// Test P2WSH (32 bytes)
	witnessProg32 := make([]byte, 32)
	for i := range witnessProg32 {
		witnessProg32[i] = byte(i)
	}

	addr32, err := CreateBech32Address(witnessProg32, GetMainnetParams())
	if err != nil {
		t.Fatalf("create P2WSH Bech32 address: %v", err)
	}

	if !strings.HasPrefix(addr32, "ltc1") {
		t.Fatalf("P2WSH Bech32 address should start with 'ltc1', got: %s", addr32)
	}

	// Test invalid witness program length
	_, err = CreateBech32Address([]byte{0x01}, GetMainnetParams())
	if err == nil {
		t.Fatalf("expected error for invalid witness program length")
	}
}

func TestNetworkParameters(t *testing.T) {
	mainnet := GetMainnetParams()

	// Test address prefixes
	if mainnet.PubKeyHashAddrID != 0x30 {
		t.Fatalf("mainnet P2PKH prefix should be 0x30, got 0x%02x", mainnet.PubKeyHashAddrID)
	}

	if mainnet.ScriptHashAddrID != 0x32 {
		t.Fatalf("mainnet P2SH prefix should be 0x32, got 0x%02x", mainnet.ScriptHashAddrID)
	}

	// Test magic number
	if mainnet.Net != 0xdbb6c0fb {
		t.Fatalf("mainnet magic should be 0xdbb6c0fb, got 0x%08x", mainnet.Net)
	}

	testnet := GetTestnetParams()

	// Test testnet prefixes
	if testnet.PubKeyHashAddrID != 0x6f {
		t.Fatalf("testnet P2PKH prefix should be 0x6f, got 0x%02x", testnet.PubKeyHashAddrID)
	}

	if testnet.ScriptHashAddrID != 0x3a {
		t.Fatalf("testnet P2SH prefix should be 0x3a, got 0x%02x", testnet.ScriptHashAddrID)
	}

	// Test testnet magic number
	if testnet.Net != 0xf1c8d2fd {
		t.Fatalf("testnet magic should be 0xf1c8d2fd, got 0x%08x", testnet.Net)
	}
}
