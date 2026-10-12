package avalanche

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestDeriveAddress(t *testing.T) {
	// Sample compressed pubkey from MPC (33 bytes)
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	addr, err := DeriveAddress(pubBytes)
	if err != nil {
		t.Fatalf("derive address error: %v", err)
	}

	// Check address format (0x + 40 hex chars)
	addrStr := addr.Hex()
	if !strings.HasPrefix(addrStr, "0x") {
		t.Fatalf("address should start with 0x, got: %s", addrStr)
	}

	if len(addrStr) != 42 { // 0x + 40 hex characters
		t.Fatalf("address should be 42 characters, got %d: %s", len(addrStr), addrStr)
	}

	// Test with invalid public key
	_, err = DeriveAddress([]byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid pubkey length")
	}
}

func TestBuildAVAXTransfer(t *testing.T) {
	// Create test private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipient := common.HexToAddress("0x742929BA7c89b7a87e1F8B9e0Ca01De7F0D15bc7")
	amount := ConvertAVAXToWei(1.5) // 1.5 AVAX
	nonce := uint64(10)

	// Test mainnet transaction
	tx, txHash, err := BuildAVAXTransfer(privateKey, recipient, amount, nonce, false)
	if err != nil {
		t.Fatalf("build AVAX transfer: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(txHash) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(txHash))
	}

	// Verify transaction fields
	if tx.To().Hex() != recipient.Hex() {
		t.Fatalf("recipient mismatch: got %s, expected %s", tx.To().Hex(), recipient.Hex())
	}

	if tx.Value().Cmp(amount) != 0 {
		t.Fatalf("amount mismatch: got %s, expected %s", tx.Value().String(), amount.String())
	}

	if tx.Nonce() != nonce {
		t.Fatalf("nonce mismatch: got %d, expected %d", tx.Nonce(), nonce)
	}

	if tx.Gas() != StandardTransferGas {
		t.Fatalf("gas limit mismatch: got %d, expected %d", tx.Gas(), StandardTransferGas)
	}

	// Test testnet transaction
	testnetTx, _, err := BuildAVAXTransfer(privateKey, recipient, amount, nonce, true)
	if err != nil {
		t.Fatalf("build testnet AVAX transfer: %v", err)
	}

	if testnetTx == nil {
		t.Fatalf("testnet transaction is nil")
	}
}

func TestBuildERC20Transfer(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipient := common.HexToAddress("0x742929BA7c89b7a87e1F8B9e0Ca01De7F0D15bc7")
	amount := ConvertUSDCToBaseUnits(100.0) // 100 USDC

	tx, txHash, err := BuildERC20Transfer(privateKey, USDCToken, recipient, amount, 5, false)
	if err != nil {
		t.Fatalf("build ERC20 transfer: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(txHash) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(txHash))
	}

	// Verify it's a contract call
	if tx.To().Hex() != USDCToken.Hex() {
		t.Fatalf("contract address mismatch: got %s, expected %s", tx.To().Hex(), USDCToken.Hex())
	}

	if tx.Value().Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("ERC20 transfer should have 0 ETH value, got %s", tx.Value().String())
	}

	if len(tx.Data()) != 68 { // 4 bytes function selector + 32 bytes address + 32 bytes amount
		t.Fatalf("expected 68 bytes data, got %d", len(tx.Data()))
	}

	// Check function selector
	expectedSelector := []byte{0xa9, 0x05, 0x9c, 0xbb} // transfer(address,uint256)
	if !bytesEqual(tx.Data()[0:4], expectedSelector) {
		t.Fatalf("function selector mismatch")
	}

	if tx.Gas() != TokenTransferGas {
		t.Fatalf("gas limit mismatch: got %d, expected %d", tx.Gas(), TokenTransferGas)
	}
}

func TestBuildUSDCTransfer(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipient := common.HexToAddress("0x742929BA7c89b7a87e1F8B9e0Ca01De7F0D15bc7")
	amount := ConvertUSDCToBaseUnits(250.50) // 250.50 USDC

	tx, txHash, err := BuildUSDCTransfer(privateKey, recipient, amount, 8, false)
	if err != nil {
		t.Fatalf("build USDC transfer: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(txHash) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(txHash))
	}

	// Should call USDC contract
	if tx.To().Hex() != USDCToken.Hex() {
		t.Fatalf("should call USDC contract: got %s, expected %s", tx.To().Hex(), USDCToken.Hex())
	}
}

func TestBuildJOETransfer(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipient := common.HexToAddress("0x742929BA7c89b7a87e1F8B9e0Ca01De7F0D15bc7")
	amount := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)) // 1000 JOE (18 decimals)

	tx, txHash, err := BuildJOETransfer(privateKey, recipient, amount, 12, false)
	if err != nil {
		t.Fatalf("build JOE transfer: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(txHash) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(txHash))
	}

	// Should call JOE contract
	if tx.To().Hex() != JOEToken.Hex() {
		t.Fatalf("should call JOE contract: got %s, expected %s", tx.To().Hex(), JOEToken.Hex())
	}
}

func TestBuildEIP1559Tx(t *testing.T) {
	recipient := common.HexToAddress("0x742929BA7c89b7a87e1F8B9e0Ca01De7F0D15bc7")
	amount := ConvertAVAXToWei(0.1) // 0.1 AVAX
	data := []byte("test data")
	nonce := uint64(15)
	gasLimit := uint64(21000)
	maxFeePerGas := big.NewInt(50000000000)        // 50 gwei
	maxPriorityFeePerGas := big.NewInt(2000000000) // 2 gwei

	// Test mainnet EIP-1559 transaction
	tx, txHash, err := BuildEIP1559Tx(recipient, amount, data, nonce, gasLimit,
		maxFeePerGas, maxPriorityFeePerGas, false)
	if err != nil {
		t.Fatalf("build EIP-1559 transaction: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(txHash) != 32 {
		t.Fatalf("expected 32-byte hash, got %d", len(txHash))
	}

	// Verify EIP-1559 specific fields
	if tx.GasFeeCap().Cmp(maxFeePerGas) != 0 {
		t.Fatalf("max fee per gas mismatch: got %s, expected %s",
			tx.GasFeeCap().String(), maxFeePerGas.String())
	}

	if tx.GasTipCap().Cmp(maxPriorityFeePerGas) != 0 {
		t.Fatalf("max priority fee per gas mismatch: got %s, expected %s",
			tx.GasTipCap().String(), maxPriorityFeePerGas.String())
	}

	// Test testnet EIP-1559 transaction
	testnetTx, _, err := BuildEIP1559Tx(recipient, amount, data, nonce, gasLimit,
		maxFeePerGas, maxPriorityFeePerGas, true)
	if err != nil {
		t.Fatalf("build testnet EIP-1559 transaction: %v", err)
	}

	if testnetTx == nil {
		t.Fatalf("testnet transaction is nil")
	}
}

func TestAttachSignature(t *testing.T) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	recipient := common.HexToAddress("0x742929BA7c89b7a87e1F8B9e0Ca01De7F0D15bc7")
	amount := ConvertAVAXToWei(1.0)

	// Build transaction
	tx, _, err := BuildAVAXTransfer(privateKey, recipient, amount, 1, false)
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}

	// Create dummy signature (65 bytes)
	signature := make([]byte, 65)
	for i := range signature {
		signature[i] = byte(i % 256)
	}

	// Test signature attachment
	signedTx, err := AttachSignature(tx, signature, false)
	if err != nil {
		t.Fatalf("attach signature: %v", err)
	}

	if signedTx == nil {
		t.Fatalf("signed transaction is nil")
	}

	// Test with invalid signature length
	_, err = AttachSignature(tx, []byte{0x01, 0x02}, false)
	if err == nil {
		t.Fatalf("expected error for invalid signature length")
	}

	// Test EIP-1559 transaction signature
	eip1559Tx, _, err := BuildEIP1559Tx(recipient, amount, nil, 1, 21000,
		big.NewInt(50000000000), big.NewInt(2000000000), false)
	if err != nil {
		t.Fatalf("build EIP-1559 transaction: %v", err)
	}

	signedEIP1559Tx, err := AttachSignature(eip1559Tx, signature, false)
	if err != nil {
		t.Fatalf("attach signature to EIP-1559: %v", err)
	}

	if signedEIP1559Tx == nil {
		t.Fatalf("signed EIP-1559 transaction is nil")
	}
}

func TestGetChainConfig(t *testing.T) {
	// Test mainnet config
	mainnetConfig := GetChainConfig(false)
	if mainnetConfig.ChainID.Int64() != AvalancheMainnetChainID {
		t.Fatalf("mainnet chain ID mismatch: got %d, expected %d",
			mainnetConfig.ChainID.Int64(), AvalancheMainnetChainID)
	}

	if mainnetConfig.LondonBlock.Int64() != 0 {
		t.Fatalf("mainnet should support EIP-1559 from block 0, got %d",
			mainnetConfig.LondonBlock.Int64())
	}

	// Test testnet config
	testnetConfig := GetChainConfig(true)
	if testnetConfig.ChainID.Int64() != AvalancheTestnetChainID {
		t.Fatalf("testnet chain ID mismatch: got %d, expected %d",
			testnetConfig.ChainID.Int64(), AvalancheTestnetChainID)
	}

	if testnetConfig.LondonBlock.Int64() != 0 {
		t.Fatalf("testnet should support EIP-1559 from block 0, got %d",
			testnetConfig.LondonBlock.Int64())
	}
}

func TestConvertAVAXToWei(t *testing.T) {
	// Test 1 AVAX = 10^18 wei
	wei := ConvertAVAXToWei(1.0)
	expected := big.NewInt(1e18)
	if wei.Cmp(expected) != 0 {
		t.Fatalf("1 AVAX should be 10^18 wei, got %s", wei.String())
	}

	// Test 0.5 AVAX
	wei = ConvertAVAXToWei(0.5)
	expected = big.NewInt(5e17)
	if wei.Cmp(expected) != 0 {
		t.Fatalf("0.5 AVAX should be 5*10^17 wei, got %s", wei.String())
	}

	// Test small amount
	wei = ConvertAVAXToWei(0.000000001) // 1 Gwei
	expected = big.NewInt(1e9)
	if wei.Cmp(expected) != 0 {
		t.Fatalf("0.000000001 AVAX should be 10^9 wei, got %s", wei.String())
	}
}

func TestConvertWeiToAVAX(t *testing.T) {
	// Test 10^18 wei = 1 AVAX
	wei := big.NewInt(1e18)
	avax := ConvertWeiToAVAX(wei)
	if avax != 1.0 {
		t.Fatalf("10^18 wei should be 1.0 AVAX, got %f", avax)
	}

	// Test round trip conversion
	originalAVAX := 2.5
	wei = ConvertAVAXToWei(originalAVAX)
	backToAVAX := ConvertWeiToAVAX(wei)

	if backToAVAX != originalAVAX {
		t.Fatalf("round trip conversion failed: original %f, back %f", originalAVAX, backToAVAX)
	}
}

func TestConvertUSDCToBaseUnits(t *testing.T) {
	// Test 1 USDC = 10^6 base units (6 decimals)
	baseUnits := ConvertUSDCToBaseUnits(1.0)
	expected := big.NewInt(1e6)
	if baseUnits.Cmp(expected) != 0 {
		t.Fatalf("1 USDC should be 10^6 base units, got %s", baseUnits.String())
	}

	// Test 100.50 USDC
	baseUnits = ConvertUSDCToBaseUnits(100.50)
	expected = big.NewInt(100500000) // 100.50 * 10^6
	if baseUnits.Cmp(expected) != 0 {
		t.Fatalf("100.50 USDC should be 100500000 base units, got %s", baseUnits.String())
	}
}

func TestConvertBaseUnitsToUSDC(t *testing.T) {
	// Test 10^6 base units = 1 USDC
	baseUnits := big.NewInt(1e6)
	usdc := ConvertBaseUnitsToUSDC(baseUnits)
	if usdc != 1.0 {
		t.Fatalf("10^6 base units should be 1.0 USDC, got %f", usdc)
	}

	// Test round trip conversion
	originalUSDC := 250.75
	baseUnits = ConvertUSDCToBaseUnits(originalUSDC)
	backToUSDC := ConvertBaseUnitsToUSDC(baseUnits)

	if backToUSDC != originalUSDC {
		t.Fatalf("round trip conversion failed: original %f, back %f", originalUSDC, backToUSDC)
	}
}

func TestGetDefaultGasPrice(t *testing.T) {
	// Test different priority levels
	slowPrice := GetDefaultGasPrice("slow")
	if slowPrice.Int64() != DefaultGasPrice {
		t.Fatalf("slow gas price mismatch: got %d, expected %d",
			slowPrice.Int64(), DefaultGasPrice)
	}

	fastPrice := GetDefaultGasPrice("fast")
	if fastPrice.Int64() != FastGasPrice {
		t.Fatalf("fast gas price mismatch: got %d, expected %d",
			fastPrice.Int64(), FastGasPrice)
	}

	instantPrice := GetDefaultGasPrice("instant")
	if instantPrice.Int64() != InstantGasPrice {
		t.Fatalf("instant gas price mismatch: got %d, expected %d",
			instantPrice.Int64(), InstantGasPrice)
	}

	defaultPrice := GetDefaultGasPrice("unknown")
	if defaultPrice.Int64() != DefaultGasPrice {
		t.Fatalf("default gas price mismatch: got %d, expected %d",
			defaultPrice.Int64(), DefaultGasPrice)
	}
}

func TestGetTokenInfo(t *testing.T) {
	// Test known tokens
	name, symbol, decimals := GetTokenInfo(USDCToken)
	if name != "USD Coin" || symbol != "USDC" || decimals != 6 {
		t.Fatalf("USDC info mismatch: got %s, %s, %d", name, symbol, decimals)
	}

	name, symbol, decimals = GetTokenInfo(JOEToken)
	if name != "JoeToken" || symbol != "JOE" || decimals != 18 {
		t.Fatalf("JOE info mismatch: got %s, %s, %d", name, symbol, decimals)
	}

	name, symbol, decimals = GetTokenInfo(WBTCToken)
	if name != "Wrapped BTC" || symbol != "WBTC.e" || decimals != 8 {
		t.Fatalf("WBTC info mismatch: got %s, %s, %d", name, symbol, decimals)
	}

	// Test unknown token
	unknownToken := common.HexToAddress("0x1234567890123456789012345678901234567890")
	name, symbol, decimals = GetTokenInfo(unknownToken)
	if name != "Unknown Token" || symbol != "???" || decimals != 18 {
		t.Fatalf("unknown token info mismatch: got %s, %s, %d", name, symbol, decimals)
	}
}

func TestIsValidAddress(t *testing.T) {
	// Test valid addresses
	validAddresses := []string{
		"0x742929BA7c89b7a87e1F8B9e0Ca01De7F0D15bc7",
		"0x0000000000000000000000000000000000000000",
		"0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7",
	}

	for _, addr := range validAddresses {
		if !IsValidAddress(addr) {
			t.Fatalf("address should be valid: %s", addr)
		}
	}

	// Test invalid addresses
	invalidAddresses := []string{
		"invalid_address",
		"0x742929BA7c89b7a87e1F8B9e0Ca01De7F0D15bc",  // too short
		"0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", // invalid hex
	}

	for _, addr := range invalidAddresses {
		if IsValidAddress(addr) {
			t.Fatalf("address should be invalid: %s", addr)
		}
	}
}

func TestGetExplorerURL(t *testing.T) {
	txHash := "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	// Test mainnet URL
	mainnetURL := GetExplorerURL(txHash, false)
	expectedMainnet := "https://snowtrace.io/tx/" + txHash
	if mainnetURL != expectedMainnet {
		t.Fatalf("mainnet URL mismatch: got %s, expected %s", mainnetURL, expectedMainnet)
	}

	// Test testnet URL
	testnetURL := GetExplorerURL(txHash, true)
	expectedTestnet := "https://testnet.snowtrace.io/tx/" + txHash
	if testnetURL != expectedTestnet {
		t.Fatalf("testnet URL mismatch: got %s, expected %s", testnetURL, expectedTestnet)
	}
}

func TestNetworkConstants(t *testing.T) {
	// Test chain IDs
	if AvalancheMainnetChainID != 43114 {
		t.Fatalf("mainnet chain ID should be 43114, got %d", AvalancheMainnetChainID)
	}

	if AvalancheTestnetChainID != 43113 {
		t.Fatalf("testnet chain ID should be 43113, got %d", AvalancheTestnetChainID)
	}

	// Test gas constants
	if StandardTransferGas != 21000 {
		t.Fatalf("standard transfer gas should be 21000, got %d", StandardTransferGas)
	}

	if TokenTransferGas != 65000 {
		t.Fatalf("token transfer gas should be 65000, got %d", TokenTransferGas)
	}

	// Test gas prices
	if DefaultGasPrice != 25000000000 {
		t.Fatalf("default gas price should be 25000000000, got %d", DefaultGasPrice)
	}

	if FastGasPrice != 35000000000 {
		t.Fatalf("fast gas price should be 35000000000, got %d", FastGasPrice)
	}
}

// Helper function to compare byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
