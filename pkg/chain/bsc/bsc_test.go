package bsc

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestDeriveAddress(t *testing.T) {
	// Sample compressed pubkey (33 bytes)
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	addr, err := DeriveAddress(pubBytes)
	if err != nil {
		t.Fatalf("derive address error: %v", err)
	}

	// BSC uses same address format as Ethereum
	if !common.IsHexAddress(addr.Hex()) {
		t.Fatalf("invalid address format: %s", addr.Hex())
	}

	if !strings.HasPrefix(addr.Hex(), "0x") {
		t.Fatalf("address should start with 0x: %s", addr.Hex())
	}

	if len(addr.Hex()) != 42 { // 0x + 40 hex chars
		t.Fatalf("address length should be 42, got %d", len(addr.Hex()))
	}
}

func TestBuildBNBTransfer(t *testing.T) {
	from := common.HexToAddress("0x742d35cc6635c0532925a3b8bc0c8ce47a9e4a8e")
	to := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
	amount := big.NewInt(1000000000000000000) // 1 BNB in wei
	nonce := uint64(0)
	gasPrice := big.NewInt(5000000000) // 5 gwei
	gasLimit := uint64(21000)

	// Test mainnet
	tx, signer, hash, err := BuildBNBTransfer(from, to, amount, nonce, gasPrice, gasLimit, true)
	if err != nil {
		t.Fatalf("build BNB transfer (mainnet): %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if hash != signer.Hash(tx) {
		t.Fatalf("returned hash does not match the signer hash")
	}

	// Verify transaction properties
	if tx.Nonce() != nonce {
		t.Fatalf("nonce mismatch: got %d, expected %d", tx.Nonce(), nonce)
	}

	if tx.Value().Cmp(amount) != 0 {
		t.Fatalf("value mismatch: got %s, expected %s", tx.Value().String(), amount.String())
	}

	if tx.GasPrice().Cmp(gasPrice) != 0 {
		t.Fatalf("gas price mismatch: got %s, expected %s", tx.GasPrice().String(), gasPrice.String())
	}

	if tx.Gas() != gasLimit {
		t.Fatalf("gas limit mismatch: got %d, expected %d", tx.Gas(), gasLimit)
	}

	// Verify chain ID through signer
	if signer == nil {
		t.Fatalf("signer is nil")
	}

	// Test testnet
	txTestnet, _, _, err := BuildBNBTransfer(from, to, amount, nonce, gasPrice, gasLimit, false)
	if err != nil {
		t.Fatalf("build BNB transfer (testnet): %v", err)
	}

	if txTestnet == nil {
		t.Fatalf("testnet transaction is nil")
	}
}

func TestBuildBEP20Transfer(t *testing.T) {
	tokenAddress := USDTAddress
	to := common.HexToAddress("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
	amount := big.NewInt(1000000000000000000) // 1 USDT (18 decimals)
	nonce := uint64(5)
	gasPrice := big.NewInt(5000000000) // 5 gwei
	gasLimit := uint64(60000)

	tx, signer, hash, err := BuildBEP20Transfer(tokenAddress, to, amount, nonce, gasPrice, gasLimit, true)
	if err != nil {
		t.Fatalf("build BEP20 transfer: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if hash != signer.Hash(tx) {
		t.Fatalf("returned hash does not match the signer hash")
	}

	// Verify transaction properties
	if tx.To().Hex() != tokenAddress.Hex() {
		t.Fatalf("to address mismatch: got %s, expected %s", tx.To().Hex(), tokenAddress.Hex())
	}

	if tx.Value().Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("BEP20 transfer should have zero value, got %s", tx.Value().String())
	}

	// Verify transaction data
	data := tx.Data()
	if len(data) != 68 { // 4 bytes selector + 32 bytes address + 32 bytes amount
		t.Fatalf("expected 68 bytes data, got %d", len(data))
	}

	// Verify function selector (transfer)
	expectedSelector := []byte{0xa9, 0x05, 0x9c, 0xbb}
	if !bytes.Equal(data[0:4], expectedSelector) {
		t.Fatalf("wrong function selector: got %x, expected %x", data[0:4], expectedSelector)
	}

	// Verify recipient address in data
	expectedRecipient := to.Bytes()
	if !bytes.Equal(data[16:36], expectedRecipient) {
		t.Fatalf("wrong recipient in data")
	}

	if signer == nil {
		t.Fatalf("signer is nil")
	}
}

func TestBuildUSDTTransfer(t *testing.T) {
	to := common.HexToAddress("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
	amount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)) // 100 USDT (18 decimals)
	nonce := uint64(10)
	gasPrice := big.NewInt(5000000000) // 5 gwei
	gasLimit := uint64(65000)

	// Test mainnet USDT transfer
	tx, signer, hash, err := BuildUSDTTransfer(to, amount, nonce, gasPrice, gasLimit, true)
	if err != nil {
		t.Fatalf("build USDT transfer (mainnet): %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if hash != signer.Hash(tx) {
		t.Fatalf("returned hash does not match the signer hash")
	}

	// Verify it's calling the correct USDT contract
	if tx.To().Hex() != USDTAddress.Hex() {
		t.Fatalf("wrong USDT contract address: got %s, expected %s", tx.To().Hex(), USDTAddress.Hex())
	}

	if signer == nil {
		t.Fatalf("signer is nil")
	}

	// Test testnet USDT transfer
	txTestnet, _, _, err := BuildUSDTTransfer(to, amount, nonce, gasPrice, gasLimit, false)
	if err != nil {
		t.Fatalf("build USDT transfer (testnet): %v", err)
	}

	if txTestnet == nil {
		t.Fatalf("testnet transaction is nil")
	}

	// Testnet should use different contract address
	if txTestnet.To().Hex() == USDTAddress.Hex() {
		t.Fatalf("testnet should use different USDT contract address")
	}
}

func TestBuildBUSDTransfer(t *testing.T) {
	to := common.HexToAddress("0xd8da6bf26964af9d7eed9e03e53415d37aa96045")
	amount := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18)) // 50 BUSD (18 decimals)
	nonce := uint64(15)
	gasPrice := big.NewInt(5000000000) // 5 gwei
	gasLimit := uint64(65000)

	// Test mainnet BUSD transfer
	tx, signer, hash, err := BuildBUSDTransfer(to, amount, nonce, gasPrice, gasLimit, true)
	if err != nil {
		t.Fatalf("build BUSD transfer (mainnet): %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if hash != signer.Hash(tx) {
		t.Fatalf("returned hash does not match the signer hash")
	}

	// Verify it's calling the correct BUSD contract
	if tx.To().Hex() != BUSDAddress.Hex() {
		t.Fatalf("wrong BUSD contract address: got %s, expected %s", tx.To().Hex(), BUSDAddress.Hex())
	}

	if signer == nil {
		t.Fatalf("signer is nil")
	}
}

func TestBuildEIP1559Tx(t *testing.T) {
	input := EIP1559TxInput{
		Nonce:                0,
		MaxFeePerGas:         big.NewInt(10000000000), // 10 gwei
		MaxPriorityFeePerGas: big.NewInt(1000000000),  // 1 gwei tip
		GasLimit:             21000,
		To:                   "0xd8da6bf26964af9d7eed9e03e53415d37aa96045",
		Value:                big.NewInt(1000000000000000000), // 1 BNB
		Data:                 nil,
		ChainID:              BSCMainnetChainID,
	}

	tx, signer, hash, err := BuildEIP1559Tx(input)
	if err != nil {
		t.Fatalf("build EIP-1559 transaction: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if hash != signer.Hash(tx) {
		t.Fatalf("returned hash does not match the signer hash")
	}

	// Verify EIP-1559 specific properties
	if tx.Type() != types.DynamicFeeTxType {
		t.Fatalf("expected DynamicFeeTxType, got %d", tx.Type())
	}

	if tx.GasFeeCap().Cmp(input.MaxFeePerGas) != 0 {
		t.Fatalf("max fee per gas mismatch: got %s, expected %s",
			tx.GasFeeCap().String(), input.MaxFeePerGas.String())
	}

	if tx.GasTipCap().Cmp(input.MaxPriorityFeePerGas) != 0 {
		t.Fatalf("max priority fee per gas mismatch: got %s, expected %s",
			tx.GasTipCap().String(), input.MaxPriorityFeePerGas.String())
	}

	if signer == nil {
		t.Fatalf("signer is nil")
	}
}

func TestAttachSignature(t *testing.T) {
	// Create a test transaction
	from := common.HexToAddress("0x742d35cc6635c0532925a3b8bc0c8ce47a9e4a8e")
	to := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
	amount := big.NewInt(1000000000000000000)

	tx, signer, _, err := BuildBNBTransfer(from, to, amount, 0, GetGasPrice(true), 21000, true)
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}

	// Create dummy 65-byte signature
	sig := make([]byte, 65)
	for i := range sig {
		sig[i] = byte(i % 256)
	}

	signedTx, err := AttachSignature(tx, signer, sig)
	if err != nil {
		t.Fatalf("attach signature: %v", err)
	}

	if signedTx == nil {
		t.Fatalf("signed transaction is nil")
	}

	// Test with invalid signature length
	_, err = AttachSignature(tx, signer, []byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid signature length")
	}
}

func TestGetGasPrice(t *testing.T) {
	mainnetPrice := GetGasPrice(true)
	if mainnetPrice.Cmp(big.NewInt(5000000000)) != 0 {
		t.Fatalf("unexpected mainnet gas price: %s", mainnetPrice.String())
	}

	testnetPrice := GetGasPrice(false)
	if testnetPrice.Cmp(big.NewInt(10000000000)) != 0 {
		t.Fatalf("unexpected testnet gas price: %s", testnetPrice.String())
	}
}

func TestGetChainID(t *testing.T) {
	mainnetChainID := GetChainID(true)
	if mainnetChainID.Cmp(BSCMainnetChainID) != 0 {
		t.Fatalf("wrong mainnet chain ID: got %s, expected %s",
			mainnetChainID.String(), BSCMainnetChainID.String())
	}

	testnetChainID := GetChainID(false)
	if testnetChainID.Cmp(BSCTestnetChainID) != 0 {
		t.Fatalf("wrong testnet chain ID: got %s, expected %s",
			testnetChainID.String(), BSCTestnetChainID.String())
	}
}

func TestTokenAddresses(t *testing.T) {
	// Test that token addresses are valid
	tokens := map[string]common.Address{
		"USDT": USDTAddress,
		"BUSD": BUSDAddress,
		"CAKE": CAKEAddress,
		"WBNB": WBNBAddress,
		"ETH":  ETHAddress,
	}

	for name, addr := range tokens {
		if !common.IsHexAddress(addr.Hex()) {
			t.Fatalf("%s address is invalid: %s", name, addr.Hex())
		}

		if addr == (common.Address{}) {
			t.Fatalf("%s address is zero address", name)
		}
	}
}

func TestSignAndRecoverSender(t *testing.T) {
	key, err := crypto.HexToECDSA("4646464646464646464646464646464646464646464646464646464646464646")
	if err != nil {
		t.Fatal(err)
	}
	from, err := DeriveAddress(crypto.CompressPubkey(&key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if from != crypto.PubkeyToAddress(key.PublicKey) {
		t.Fatalf("DeriveAddress = %s, want %s", from.Hex(), crypto.PubkeyToAddress(key.PublicKey).Hex())
	}
	to := "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"

	legacy := func(isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {
		return BuildBNBTransfer(from, to, big.NewInt(1), 7, big.NewInt(1_000_000_000), 21000, isMainnet)
	}
	dynamic := func(isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {
		return BuildEIP1559Tx(EIP1559TxInput{
			Nonce:                7,
			MaxFeePerGas:         big.NewInt(2_000_000_000),
			MaxPriorityFeePerGas: big.NewInt(1_000_000_000),
			GasLimit:             21000,
			To:                   to,
			Value:                big.NewInt(1),
			ChainID:              GetChainID(isMainnet),
		})
	}

	for name, build := range map[string]func(bool) (*types.Transaction, types.Signer, [32]byte, error){
		"legacy":   legacy,
		"eip-1559": dynamic,
	} {
		for _, isMainnet := range []bool{true, false} {
			tx, signer, hash, err := build(isMainnet)
			if err != nil {
				t.Fatalf("%s: build: %v", name, err)
			}
			if signer.Hash(tx) != hash {
				t.Fatalf("%s: returned hash does not match signer hash", name)
			}
			raw, err := crypto.Sign(hash[:], key)
			if err != nil {
				t.Fatal(err)
			}
			// A threshold signer only returns r||s; recover V from the public key.
			sig, err := BuildSignature65(hash, crypto.CompressPubkey(&key.PublicKey), hex.EncodeToString(raw[:64]))
			if err != nil {
				t.Fatalf("%s: BuildSignature65: %v", name, err)
			}
			signed, err := AttachSignature(tx, signer, sig)
			if err != nil {
				t.Fatalf("%s: AttachSignature: %v", name, err)
			}
			sender, err := types.Sender(signer, signed)
			if err != nil {
				t.Fatalf("%s: Sender: %v", name, err)
			}
			if sender != from {
				t.Fatalf("%s: sender = %s, want %s", name, sender.Hex(), from.Hex())
			}
			if signed.ChainId().Cmp(GetChainID(isMainnet)) != 0 {
				t.Fatalf("%s: chain ID = %s, want %s", name, signed.ChainId(), GetChainID(isMainnet))
			}
		}
	}

	if _, err := BuildSignature65([32]byte{1}, crypto.CompressPubkey(&key.PublicKey), "invalid"); err == nil {
		t.Fatal("expected error for malformed signature")
	}
	if _, _, _, err := BuildBEP20Transfer(common.Address{}, from, big.NewInt(-1), 0, big.NewInt(1), 60000, true); err == nil {
		t.Fatal("expected error for negative token amount")
	}
}

func TestBuildersRejectInvalidRecipient(t *testing.T) {
	for _, to := range []string{
		"0x7E5F4552091A69125d5DfCb7b8C2659029395Bd",  // one hex digit missing
		"0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf", // bad EIP-55 checksum
		"7E5F4552091A69125d5DfCb7b8C2659029395Bdf",   // no 0x prefix
	} {
		if _, _, _, err := BuildLegacyTx(LegacyTxInput{To: to, Value: big.NewInt(1), GasPrice: big.NewInt(1), GasLimit: 21000}); err == nil {
			t.Errorf("BuildLegacyTx accepted recipient %q", to)
		}
		if _, _, _, err := BuildEIP1559Tx(EIP1559TxInput{To: to, Value: big.NewInt(1), MaxFeePerGas: big.NewInt(2), MaxPriorityFeePerGas: big.NewInt(1), GasLimit: 21000}); err == nil {
			t.Errorf("BuildEIP1559Tx accepted recipient %q", to)
		}
	}
}
