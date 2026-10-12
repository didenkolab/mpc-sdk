package near

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestDeriveAddress(t *testing.T) {
	// Sample Ed25519 public key from FROST MPC (32 bytes)
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 1)
	}

	addr, err := DeriveAddress(pubKey)
	if err != nil {
		t.Fatalf("derive address error: %v", err)
	}

	// NEAR addresses are hex representation of public key
	expectedAddr := hex.EncodeToString(pubKey)
	if addr != expectedAddr {
		t.Fatalf("address mismatch: got %s, expected %s", addr, expectedAddr)
	}

	if len(addr) != 64 { // 32 bytes = 64 hex chars
		t.Fatalf("address length should be 64, got %d", len(addr))
	}
}

func TestDeriveImplicitAddress(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 10)
	}

	addr, err := DeriveImplicitAddress(pubKey)
	if err != nil {
		t.Fatalf("derive implicit address error: %v", err)
	}

	expectedAddr := hex.EncodeToString(pubKey)
	if addr != expectedAddr {
		t.Fatalf("implicit address mismatch: got %s, expected %s", addr, expectedAddr)
	}

	// Test with invalid key length
	_, err = DeriveImplicitAddress([]byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid key length")
	}
}

func TestDeriveNamedAddress(t *testing.T) {
	// Test mainnet named address
	addr, err := DeriveNamedAddress("alice", false)
	if err != nil {
		t.Fatalf("derive named address error: %v", err)
	}

	expectedAddr := "alice.near"
	if addr != expectedAddr {
		t.Fatalf("named address mismatch: got %s, expected %s", addr, expectedAddr)
	}

	// Test testnet named address
	testnetAddr, err := DeriveNamedAddress("bob", true)
	if err != nil {
		t.Fatalf("derive testnet named address error: %v", err)
	}

	expectedTestnetAddr := "bob.testnet"
	if testnetAddr != expectedTestnetAddr {
		t.Fatalf("testnet address mismatch: got %s, expected %s", testnetAddr, expectedTestnetAddr)
	}

	// Test with empty account name
	_, err = DeriveNamedAddress("", false)
	if err == nil {
		t.Fatalf("expected error for empty account name")
	}
}

func TestBuildTransferTransaction(t *testing.T) {
	// FROST MPC Ed25519 public key
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 5)
	}

	// Sample block hash
	blockHash := make([]byte, 32)
	for i := range blockHash {
		blockHash[i] = byte(i + 100)
	}

	signerID := "sender.testnet"
	receiverID := "receiver.testnet"
	amount := ConvertNEARToYocto(1.0) // 1 NEAR
	nonce := uint64(42)

	tx, serialized, err := BuildTransferTransaction(
		signerID, receiverID, amount, nonce, blockHash, pubKey, true)
	if err != nil {
		t.Fatalf("build transfer transaction: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if serialized == nil {
		t.Fatalf("serialized transaction is nil")
	}

	// Verify transaction properties
	if tx.SignerID != signerID {
		t.Fatalf("signer ID mismatch: got %s, expected %s", tx.SignerID, signerID)
	}

	if tx.ReceiverID != receiverID {
		t.Fatalf("receiver ID mismatch: got %s, expected %s", tx.ReceiverID, receiverID)
	}

	if tx.Nonce != nonce {
		t.Fatalf("nonce mismatch: got %d, expected %d", tx.Nonce, nonce)
	}

	if !bytes.Equal(tx.BlockHash, blockHash) {
		t.Fatalf("block hash mismatch")
	}

	if !bytes.Equal(tx.PublicKey.Data, pubKey) {
		t.Fatalf("public key mismatch")
	}

	if len(tx.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(tx.Actions))
	}

	if tx.Actions[0].Type != ActionTypeTransfer {
		t.Fatalf("expected transfer action, got type %d", tx.Actions[0].Type)
	}

	// Test with invalid public key
	_, _, err = BuildTransferTransaction(signerID, receiverID, amount, nonce, blockHash, []byte{0x01}, true)
	if err == nil {
		t.Fatalf("expected error for invalid public key")
	}

	// Test with invalid block hash
	_, _, err = BuildTransferTransaction(signerID, receiverID, amount, nonce, []byte{0x01}, pubKey, true)
	if err == nil {
		t.Fatalf("expected error for invalid block hash")
	}
}

func TestBuildFunctionCallTransaction(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 15)
	}

	blockHash := make([]byte, 32)
	for i := range blockHash {
		blockHash[i] = byte(i + 150)
	}

	signerID := "caller.testnet"
	receiverID := "contract.testnet"
	methodName := "transfer"
	args := []byte(`{"to": "recipient.testnet", "amount": "1000000000000000000000000"}`)
	gas := uint64(100000000000000) // 100 TGas
	deposit := ConvertNEARToYocto(0.1)
	nonce := uint64(123)

	tx, serialized, err := BuildFunctionCallTransaction(
		signerID, receiverID, methodName, args, gas, deposit, nonce, blockHash, pubKey, true)
	if err != nil {
		t.Fatalf("build function call transaction: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if serialized == nil {
		t.Fatalf("serialized transaction is nil")
	}

	// Verify transaction properties
	if tx.SignerID != signerID {
		t.Fatalf("signer ID mismatch")
	}

	if tx.ReceiverID != receiverID {
		t.Fatalf("receiver ID mismatch")
	}

	if len(tx.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(tx.Actions))
	}

	if tx.Actions[0].Type != ActionTypeFunctionCall {
		t.Fatalf("expected function call action, got type %d", tx.Actions[0].Type)
	}

	funcCall := tx.Actions[0].Data.(FunctionCallAction)
	if funcCall.MethodName != methodName {
		t.Fatalf("method name mismatch: got %s, expected %s", funcCall.MethodName, methodName)
	}

	if !bytes.Equal(funcCall.Args, args) {
		t.Fatalf("args mismatch")
	}

	if funcCall.Gas != gas {
		t.Fatalf("gas mismatch: got %d, expected %d", funcCall.Gas, gas)
	}
}

func TestBuildStakeTransaction(t *testing.T) {
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 25)
	}

	blockHash := make([]byte, 32)
	for i := range blockHash {
		blockHash[i] = byte(i + 200)
	}

	signerID := "staker.testnet"
	validatorID := "validator.testnet"
	stakeAmount := ConvertNEARToYocto(100.0) // 100 NEAR
	nonce := uint64(456)

	tx, serialized, err := BuildStakeTransaction(
		signerID, validatorID, stakeAmount, nonce, blockHash, pubKey, true)
	if err != nil {
		t.Fatalf("build stake transaction: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if serialized == nil {
		t.Fatalf("serialized transaction is nil")
	}

	// Verify transaction properties
	if tx.SignerID != signerID {
		t.Fatalf("signer ID mismatch")
	}

	if tx.ReceiverID != validatorID {
		t.Fatalf("validator ID mismatch")
	}

	if len(tx.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(tx.Actions))
	}

	if tx.Actions[0].Type != ActionTypeStake {
		t.Fatalf("expected stake action, got type %d", tx.Actions[0].Type)
	}

	stakeAction := tx.Actions[0].Data.(StakeAction)
	if stakeAction.Stake.Cmp(stakeAmount) != 0 {
		t.Fatalf("stake amount mismatch")
	}
}

func TestAttachSignature(t *testing.T) {
	// Create test transaction
	pubKey := make([]byte, 32)
	blockHash := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
		blockHash[i] = byte(i + 50)
	}

	tx, _, err := BuildTransferTransaction(
		"sender.testnet", "receiver.testnet",
		ConvertNEARToYocto(1.0), 0, blockHash, pubKey, true)
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}

	// Create dummy 64-byte Ed25519 signature
	sig := make([]byte, 64)
	rand.Read(sig)

	signedTx, err := AttachSignature(tx, sig)
	if err != nil {
		t.Fatalf("attach signature: %v", err)
	}

	if signedTx == nil {
		t.Fatalf("signed transaction is nil")
	}

	if signedTx.Transaction != tx {
		t.Fatalf("transaction reference mismatch")
	}

	if !bytes.Equal(signedTx.Signature.Signature, sig) {
		t.Fatalf("signature mismatch")
	}

	if signedTx.Signature.KeyType != 0 {
		t.Fatalf("expected Ed25519 key type (0), got %d", signedTx.Signature.KeyType)
	}

	// Test with invalid signature length
	_, err = AttachSignature(tx, []byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid signature length")
	}
}

func TestSerializeTransaction(t *testing.T) {
	pubKey := make([]byte, 32)
	blockHash := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
		blockHash[i] = byte(i + 100)
	}

	tx, serialized, err := BuildTransferTransaction(
		"alice.testnet", "bob.testnet",
		ConvertNEARToYocto(2.5), 789, blockHash, pubKey, true)
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}

	// Verify serialization is not empty
	if len(serialized) == 0 {
		t.Fatalf("serialized transaction is empty")
	}

	if hash := HashTransaction(serialized); hash != sha256.Sum256(serialized) {
		t.Fatalf("HashTransaction must be SHA-256 of the serialized transaction")
	}

	// Test serialization consistency
	serialized2, err := SerializeTransaction(tx)
	if err != nil {
		t.Fatalf("second serialization: %v", err)
	}

	if !bytes.Equal(serialized, serialized2) {
		t.Fatalf("serialization not deterministic")
	}
}

func TestSerializeSignedTransaction(t *testing.T) {
	pubKey := make([]byte, 32)
	blockHash := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i + 1)
		blockHash[i] = byte(i + 2)
	}

	tx, serialized, err := BuildTransferTransaction(
		"alice.testnet", "bob.testnet",
		ConvertNEARToYocto(1.0), 1, blockHash, pubKey, true)
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}

	hash := HashTransaction(serialized)
	sig := make([]byte, 64)
	copy(sig, hash[:])

	signed, err := AttachSignature(tx, sig)
	if err != nil {
		t.Fatalf("attach signature: %v", err)
	}

	raw, err := SerializeSignedTransaction(signed)
	if err != nil {
		t.Fatalf("serialize signed tx: %v", err)
	}

	if len(raw) != len(serialized)+1+64 {
		t.Fatalf("unexpected signed tx length: got %d", len(raw))
	}

	// Deterministic
	raw2, err := SerializeSignedTransaction(signed)
	if err != nil {
		t.Fatalf("serialize signed tx 2: %v", err)
	}
	if !bytes.Equal(raw, raw2) {
		t.Fatalf("signed tx serialization not deterministic")
	}

	// Base64 helper
	if b64, err := EncodeSignedTransactionBase64(signed); err != nil || b64 == "" {
		t.Fatalf("base64 encoding failed: %v", err)
	}

	// Invalid signature length
	signed.Signature.Signature = []byte{0x01}
	if _, err := SerializeSignedTransaction(signed); err == nil {
		t.Fatalf("expected error for invalid signature length")
	}
}

func TestHashTransaction(t *testing.T) {
	serialized := []byte("test transaction data")
	hash := HashTransaction(serialized)

	if hash != sha256.Sum256(serialized) {
		t.Fatalf("HashTransaction must be SHA-256 of the serialized transaction")
	}

	// Test that same input produces same hash
	hash2 := HashTransaction(serialized)
	if !bytes.Equal(hash[:], hash2[:]) {
		t.Fatalf("hash function not deterministic")
	}

	// Test that different input produces different hash
	hash3 := HashTransaction([]byte("different data"))
	if bytes.Equal(hash[:], hash3[:]) {
		t.Fatalf("different inputs produced same hash")
	}
}

func TestBuildSignature64(t *testing.T) {
	// Generate test Ed25519 key pair
	privateKey := make([]byte, 64)
	rand.Read(privateKey)

	hash := [32]byte{}
	for i := range hash {
		hash[i] = byte(i)
	}

	sig, err := BuildSignature64(hash, privateKey)
	if err != nil {
		t.Fatalf("build signature: %v", err)
	}

	if len(sig) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(sig))
	}

	// Test with invalid private key length
	_, err = BuildSignature64(hash, []byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid private key length")
	}
}

func TestGetDefaultGas(t *testing.T) {
	transferGas := GetDefaultGas("transfer")
	if transferGas != 30000000000000 {
		t.Fatalf("unexpected transfer gas: %d", transferGas)
	}

	functionCallGas := GetDefaultGas("function_call")
	if functionCallGas != 100000000000000 {
		t.Fatalf("unexpected function call gas: %d", functionCallGas)
	}

	stakeGas := GetDefaultGas("stake")
	if stakeGas != 50000000000000 {
		t.Fatalf("unexpected stake gas: %d", stakeGas)
	}

	defaultGas := GetDefaultGas("unknown")
	if defaultGas != 30000000000000 {
		t.Fatalf("unexpected default gas: %d", defaultGas)
	}
}

func TestGetDefaultDeposit(t *testing.T) {
	transferDeposit := GetDefaultDeposit("transfer")
	if transferDeposit.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("unexpected transfer deposit: %s", transferDeposit.String())
	}

	functionCallDeposit := GetDefaultDeposit("function_call")
	if functionCallDeposit.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("unexpected function call deposit: %s", functionCallDeposit.String())
	}
}

func TestConvertNEARToYocto(t *testing.T) {
	// Test 1 NEAR = 10^24 yoctoNEAR
	oneNEAR := ConvertNEARToYocto(1.0)
	expected := new(big.Int)
	expected.Exp(big.NewInt(10), big.NewInt(24), nil)

	if oneNEAR.Cmp(expected) != 0 {
		t.Fatalf("1 NEAR conversion: got %s, expected %s", oneNEAR.String(), expected.String())
	}

	// Test 2.5 NEAR
	twoFiveNEAR := ConvertNEARToYocto(2.5)
	expectedTwoFive := new(big.Int).Mul(expected, big.NewInt(25))
	expectedTwoFive.Div(expectedTwoFive, big.NewInt(10))

	if twoFiveNEAR.Cmp(expectedTwoFive) != 0 {
		t.Fatalf("2.5 NEAR conversion: got %s, expected %s", twoFiveNEAR.String(), expectedTwoFive.String())
	}
}

func TestConvertYoctoToNEAR(t *testing.T) {
	// Test 10^24 yoctoNEAR = 1 NEAR
	yoctoAmount := new(big.Int)
	yoctoAmount.Exp(big.NewInt(10), big.NewInt(24), nil)

	nearAmount := ConvertYoctoToNEAR(yoctoAmount)
	if nearAmount != 1.0 {
		t.Fatalf("yocto to NEAR conversion: got %f, expected 1.0", nearAmount)
	}

	// Test round trip conversion
	originalNEAR := 3.14159
	yocto := ConvertNEARToYocto(originalNEAR)
	backToNEAR := ConvertYoctoToNEAR(yocto)

	// Allow small floating point precision difference
	diff := originalNEAR - backToNEAR
	if diff < -0.000001 || diff > 0.000001 {
		t.Fatalf("round trip conversion failed: original %f, back %f", originalNEAR, backToNEAR)
	}
}

func TestEncodeDecodeBase58(t *testing.T) {
	testData := []byte("hello world")

	encoded := EncodeBase58(testData)
	if encoded == "" {
		t.Fatalf("base58 encoding failed")
	}

	decoded, err := DecodeBase58(encoded)
	if err != nil {
		t.Fatalf("base58 decoding failed: %v", err)
	}

	if !bytes.Equal(testData, decoded) {
		t.Fatalf("base58 round trip failed: original %x, decoded %x", testData, decoded)
	}
}

func TestNEARPublicKey(t *testing.T) {
	pubKey := NEARPublicKey{
		KeyType: 0,
		Data:    make([]byte, 32),
	}

	for i := range pubKey.Data {
		pubKey.Data[i] = byte(i)
	}

	if pubKey.KeyType != 0 {
		t.Fatalf("expected Ed25519 key type (0), got %d", pubKey.KeyType)
	}

	if len(pubKey.Data) != 32 {
		t.Fatalf("expected 32-byte key data, got %d", len(pubKey.Data))
	}
}

func TestActionTypes(t *testing.T) {
	// Test that all action types have expected values
	if ActionTypeCreateAccount != 0 {
		t.Fatalf("CreateAccount action type should be 0, got %d", ActionTypeCreateAccount)
	}

	if ActionTypeTransfer != 3 {
		t.Fatalf("Transfer action type should be 3, got %d", ActionTypeTransfer)
	}

	if ActionTypeFunctionCall != 2 {
		t.Fatalf("FunctionCall action type should be 2, got %d", ActionTypeFunctionCall)
	}

	if ActionTypeStake != 4 {
		t.Fatalf("Stake action type should be 4, got %d", ActionTypeStake)
	}
}

func TestChainIDs(t *testing.T) {
	if NEARMainnetChainID != "mainnet" {
		t.Fatalf("NEAR mainnet chain ID should be 'mainnet', got %s", NEARMainnetChainID)
	}

	if NEARTestnetChainID != "testnet" {
		t.Fatalf("NEAR testnet chain ID should be 'testnet', got %s", NEARTestnetChainID)
	}
}

func TestTokenContracts(t *testing.T) {
	if NEARNativeToken != "NEAR" {
		t.Fatalf("NEAR native token should be 'NEAR', got %s", NEARNativeToken)
	}

	// Test that contract addresses are not empty
	if USDCContract == "" {
		t.Fatalf("USDC contract address should not be empty")
	}

	if USDTContract == "" {
		t.Fatalf("USDT contract address should not be empty")
	}

	if WETHContract == "" {
		t.Fatalf("WETH contract address should not be empty")
	}
}
