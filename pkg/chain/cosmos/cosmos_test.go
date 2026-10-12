package cosmos

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/bech32"
)

func TestDeriveAddress(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	addr, err := DeriveAddress(pubBytes, "cosmos")
	if err != nil {
		t.Fatalf("derive address error: %v", err)
	}
	hrp, data, err := bech32.Decode(addr)
	if err != nil {
		t.Fatalf("decode bech32: %v", err)
	}
	if hrp != "cosmos" {
		t.Fatalf("unexpected hrp: %s", hrp)
	}
	decoded, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		t.Fatalf("convert bits: %v", err)
	}
	if len(decoded) != 20 {
		t.Fatalf("expected hash160 length 20, got %d", len(decoded))
	}
}

func TestDeriveAddressKnownVector(t *testing.T) {
	// Public key of private key 1 (generator G). Its HASH160 is the payload
	// of Bitcoin address 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH; Cosmos SDK
	// secp256k1 account addresses use the same RIPEMD160(SHA256(pubkey)).
	pub, _ := hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	hash160, _ := hex.DecodeString("751e76e8199196d454941c45d1b3a323f1433bd6")

	for _, hrp := range []string{"cosmos", "osmo"} {
		got, err := DeriveAddress(pub, hrp)
		if err != nil {
			t.Fatal(err)
		}
		conv, _ := bech32.ConvertBits(hash160, 8, 5, true)
		want, _ := bech32.Encode(hrp, conv)
		if got != want {
			t.Errorf("DeriveAddress(%s) = %s, want %s", hrp, got, want)
		}
	}

	for name, bad := range map[string]string{
		"uncompressed length": "04" + strings.Repeat("11", 64),
		"not on curve":        "02" + strings.Repeat("ff", 32),
	} {
		b, _ := hex.DecodeString(bad)
		if _, err := DeriveAddress(b, "cosmos"); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestBuildTransferTx(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	fromAddr, err := DeriveAddress(pubBytes, "cosmos")
	if err != nil {
		t.Fatalf("derive from address: %v", err)
	}

	toAddr := "cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"

	amount := []Coin{{
		Denom:  "uatom",
		Amount: "1000000",
	}}

	fee := Fee{
		Amount: []Coin{{
			Denom:  "uatom",
			Amount: "5000",
		}},
		GasLimit: 200000,
	}

	signDoc, err := BuildTransferTx(fromAddr, toAddr, amount, 0, 1, "cosmoshub-4", fee, "test memo", pubBytes)
	if err != nil {
		t.Fatalf("build transfer tx: %v", err)
	}

	if signDoc == nil {
		t.Fatalf("sign doc is nil")
	}

	if signDoc.ChainID != "cosmoshub-4" {
		t.Fatalf("unexpected chain ID: %s", signDoc.ChainID)
	}

	if signDoc.AccountNumber != 1 {
		t.Fatalf("unexpected account number: %d", signDoc.AccountNumber)
	}
}

func TestBuildDelegateTx(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	delegatorAddr, err := DeriveAddress(pubBytes, "cosmos")
	if err != nil {
		t.Fatalf("derive delegator address: %v", err)
	}

	validatorAddr := "cosmosvaloper1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"

	amount := Coin{
		Denom:  "uatom",
		Amount: "1000000",
	}

	fee := Fee{
		Amount: []Coin{{
			Denom:  "uatom",
			Amount: "5000",
		}},
		GasLimit: 200000,
	}

	signDoc, err := BuildDelegateTx(delegatorAddr, validatorAddr, amount, 0, 1, "cosmoshub-4", fee, "", pubBytes)
	if err != nil {
		t.Fatalf("build delegate tx: %v", err)
	}

	if signDoc == nil {
		t.Fatalf("sign doc is nil")
	}

	if signDoc.ChainID != "cosmoshub-4" {
		t.Fatalf("unexpected chain ID: %s", signDoc.ChainID)
	}
}

func TestBuildUndelegateTx(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	delegatorAddr, err := DeriveAddress(pubBytes, "cosmos")
	if err != nil {
		t.Fatalf("derive delegator address: %v", err)
	}

	validatorAddr := "cosmosvaloper1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5lzv7xu"

	amount := Coin{
		Denom:  "uatom",
		Amount: "500000",
	}

	fee := Fee{
		Amount: []Coin{{
			Denom:  "uatom",
			Amount: "5000",
		}},
		GasLimit: 250000,
	}

	signDoc, err := BuildUndelegateTx(delegatorAddr, validatorAddr, amount, 1, 1, "cosmoshub-4", fee, "", pubBytes)
	if err != nil {
		t.Fatalf("build undelegate tx: %v", err)
	}

	if signDoc == nil {
		t.Fatalf("sign doc is nil")
	}
}

func TestBuildVoteTx(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	voter, err := DeriveAddress(pubBytes, "cosmos")
	if err != nil {
		t.Fatalf("derive voter address: %v", err)
	}

	fee := Fee{
		Amount: []Coin{{
			Denom:  "uatom",
			Amount: "2000",
		}},
		GasLimit: 100000,
	}

	signDoc, err := BuildVoteTx(voter, "1", VoteOptionYes, 2, 1, "cosmoshub-4", fee, "", pubBytes)
	if err != nil {
		t.Fatalf("build vote tx: %v", err)
	}

	if signDoc == nil {
		t.Fatalf("sign doc is nil")
	}

	if signDoc.AccountNumber != 1 {
		t.Fatalf("unexpected account number: %d", signDoc.AccountNumber)
	}
}

func TestHashSignDoc(t *testing.T) {
	testData := []byte("test sign doc data")
	hash := HashSignDoc(testData)

	if hash != sha256.Sum256(testData) {
		t.Fatalf("HashSignDoc must be SHA-256 of the sign bytes")
	}

	// Test deterministic hashing
	hash2 := HashSignDoc(testData)
	if hash != hash2 {
		t.Fatalf("hash should be deterministic")
	}
}

func TestHexSignDoc(t *testing.T) {
	testData := []byte("test data")
	hexHash := HexSignDoc(testData)

	if len(hexHash) != 64 {
		t.Fatalf("expected 64-character hex string, got %d", len(hexHash))
	}

	// Verify it's valid hex
	_, err := hex.DecodeString(hexHash)
	if err != nil {
		t.Fatalf("invalid hex string: %v", err)
	}
}

func TestVoteOptions(t *testing.T) {
	options := []VoteOption{
		VoteOptionYes,
		VoteOptionAbstain,
		VoteOptionNo,
		VoteOptionNoWithVeto,
	}

	expectedValues := []string{
		"VOTE_OPTION_YES",
		"VOTE_OPTION_ABSTAIN",
		"VOTE_OPTION_NO",
		"VOTE_OPTION_NO_WITH_VETO",
	}

	for i, option := range options {
		if string(option) != expectedValues[i] {
			t.Fatalf("unexpected vote option value: got %s, expected %s", string(option), expectedValues[i])
		}
	}
}
