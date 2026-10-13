package tron

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

func TestDeriveAddress(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	addr, err := DeriveAddress(pubBytes)
	if err != nil {
		t.Fatalf("derive address error: %v", err)
	}

	raw, err := base58.Decode(addr)
	if err != nil {
		t.Fatalf("base58 decode: %v", err)
	}
	if len(raw) < 5 {
		t.Fatalf("unexpected decoded length: %d", len(raw))
	}
	if raw[0] != 0x41 {
		t.Fatalf("expected prefix 0x41, got 0x%x", raw[0])
	}
}

func TestBuildTRXTransfer(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	fromAddr, err := DeriveAddress(pubBytes)
	if err != nil {
		t.Fatalf("derive from address: %v", err)
	}

	// Generate a different address for 'to'
	toAddr := "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" // USDT contract address for testing

	amount := uint64(1000000) // 1 TRX in SUN
	refBlockBytes := "1234"
	refBlockHash := "abcdef1234567890"
	expiration := int64(1640995200000) // timestamp
	timestamp := int64(1640995100000)

	tx, payload, err := BuildTRXTransfer(fromAddr, toAddr, amount, refBlockBytes, refBlockHash, expiration, timestamp)
	if err != nil {
		t.Fatalf("build TRX transfer: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(payload) == 0 {
		t.Fatalf("payload is empty")
	}

	// Check transaction structure
	if len(tx.RawData.Contract) != 1 {
		t.Fatalf("expected 1 contract, got %d", len(tx.RawData.Contract))
	}

	contract := tx.RawData.Contract[0]
	if contract.Type != ContractTypeTransfer {
		t.Fatalf("unexpected contract type: %s", contract.Type)
	}

	if hex.EncodeToString(tx.RawData.RefBlockBytes) != refBlockBytes {
		t.Fatalf("unexpected ref block bytes: %x", tx.RawData.RefBlockBytes)
	}

	if hex.EncodeToString(tx.RawData.RefBlockHash) != refBlockHash {
		t.Fatalf("unexpected ref block hash: %x", tx.RawData.RefBlockHash)
	}
}

func TestBuildTRC20Transfer(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	fromAddr, err := DeriveAddress(pubBytes)
	if err != nil {
		t.Fatalf("derive from address: %v", err)
	}

	contractAddr := "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" // USDT contract
	toAddr := "TLBaRhANQoJFTqre9Nf1mjuwNWjCJeYqUL"       // example address

	amount := uint64(1000000) // 1 USDT (assuming 6 decimals)
	refBlockBytes := "5678"
	refBlockHash := "fedcba9876543210"
	expiration := int64(1640995300000)
	timestamp := int64(1640995200000)
	feeLimit := uint64(10000000) // 10 TRX fee limit

	tx, payload, err := BuildTRC20Transfer(fromAddr, contractAddr, toAddr, amount,
		refBlockBytes, refBlockHash, expiration, timestamp, feeLimit)
	if err != nil {
		t.Fatalf("build TRC20 transfer: %v", err)
	}

	if tx == nil {
		t.Fatalf("transaction is nil")
	}

	if len(payload) == 0 {
		t.Fatalf("payload is empty")
	}

	// Check transaction structure
	if len(tx.RawData.Contract) != 1 {
		t.Fatalf("expected 1 contract, got %d", len(tx.RawData.Contract))
	}

	contract := tx.RawData.Contract[0]
	if contract.Type != ContractTypeTriggerSmartContract {
		t.Fatalf("unexpected contract type: %s", contract.Type)
	}

	if tx.RawData.FeeLimit != feeLimit {
		t.Fatalf("unexpected fee limit: %d", tx.RawData.FeeLimit)
	}
}

func TestAttachSignature(t *testing.T) {
	pubHex := "022b4a98d254f46bc1933993de7d82c2b0eaf9fbba2d2ac376d4090f23517551f7"
	pubBytes, _ := hex.DecodeString(pubHex)

	fromAddr, _ := DeriveAddress(pubBytes)
	toAddr := "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

	tx, _, err := BuildTRXTransfer(fromAddr, toAddr, 1000000, "1234", "abcdef1234567890", 1640995200000, 1640995100000)
	if err != nil {
		t.Fatalf("build transaction: %v", err)
	}

	// Dummy signature (65 bytes)
	signature := make([]byte, 65)
	for i := range signature {
		signature[i] = byte(i)
	}

	AttachSignature(tx, signature)

	if len(tx.Signature) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(tx.Signature))
	}

	expectedSigHex := hex.EncodeToString(signature)
	if tx.Signature[0] != expectedSigHex {
		t.Fatalf("signature mismatch: got %s, expected %s", tx.Signature[0], expectedSigHex)
	}
}

func TestIsValidTronAddress(t *testing.T) {
	testCases := []struct {
		addr    string
		isValid bool
		desc    string
	}{
		{"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", true, "valid USDT contract address"},
		{"TLBaRhANQoJFTqre9Nf1mjuwNWjCJeYqUL", true, "valid user address"},
		{"invalid", false, "too short"},
		{"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6tX", false, "too long"},
		{"ZR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", false, "invalid prefix after decode"},
	}

	for _, tc := range testCases {
		result := isValidTronAddress(tc.addr)
		if result != tc.isValid {
			t.Fatalf("address validation failed for %s (%s): got %v, expected %v",
				tc.addr, tc.desc, result, tc.isValid)
		}
	}
}

func TestBase58AddressToHex(t *testing.T) {
	// Test with a known valid address
	addr := "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
	hexAddr, err := base58AddressToHex(addr)
	if err != nil {
		t.Fatalf("base58 to hex conversion failed: %v", err)
	}

	if !strings.HasPrefix(hexAddr, "0x41") {
		t.Fatalf("hex address should start with 0x41, got: %s", hexAddr)
	}

	if len(hexAddr) != 44 { // 0x + 41 + 40 hex chars (20 bytes)
		t.Fatalf("hex address should be 44 characters long, got %d: %s", len(hexAddr), hexAddr)
	}
}

func TestHashPayload(t *testing.T) {
	testData := []byte("test payload for hashing")
	hash := HashPayload(testData)

	if hash != sha256.Sum256(testData) {
		t.Fatalf("HashPayload must be SHA-256 of the payload")
	}

	// Test deterministic hashing
	hash2 := HashPayload(testData)
	if hash != hash2 {
		t.Fatalf("hash should be deterministic")
	}

	// Test different input produces different hash
	hash3 := HashPayload([]byte("different data"))
	if hash == hash3 {
		t.Fatalf("different inputs should produce different hashes")
	}
}

func TestPackAmount(t *testing.T) {
	testCases := []struct {
		amount   uint64
		expected []byte
	}{
		{0, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{1, []byte{0, 0, 0, 0, 0, 0, 0, 1}},
		{256, []byte{0, 0, 0, 0, 0, 0, 1, 0}},
		{1000000, []byte{0, 0, 0, 0, 0, 15, 66, 64}}, // 1 TRX in SUN
	}

	for _, tc := range testCases {
		result := PackAmount(tc.amount)
		if len(result) != 8 {
			t.Fatalf("packed amount should be 8 bytes, got %d", len(result))
		}

		for i, expected := range tc.expected {
			if result[i] != expected {
				t.Fatalf("amount %d: byte %d mismatch: got %d, expected %d",
					tc.amount, i, result[i], expected)
			}
		}
	}
}

// TestBuildTRXTransferMatchesNode pins a transfer built by a Nile testnet node
// (wallet/createtransaction): the SDK must produce byte-identical raw_data and
// the same txID, otherwise the network rejects the signature.
func TestBuildTRXTransferMatchesNode(t *testing.T) {
	const (
		nodeRawHex = "0a0229292208d7a4a9309e76405a40f0aef69393345a65080112610a2d747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5472616e73666572436f6e747261637412300a1541f7c3feccb6461aab0fd25f61d9560645b08228cb121541a614f803b6fd780986a42c78ec9c7f77e6ded13c180170cfddf2939334"
		nodeTxID   = "bdb4daa470cc2e6ee91dbdbe6ee842d3dcfa0c35f03e35b5acbba8301206b384"
	)
	_, raw, err := BuildTRXTransfer("TYZGhS8UG5okCZneaJoYZJJhsqeD6ZZZZZ", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", 1,
		"2929", "d7a4a9309e76405a", 1791848454000, 1791848394447)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(raw); got != nodeRawHex {
		t.Fatalf("raw_data differs from the node:\n got %s\nwant %s", got, nodeRawHex)
	}
	if id := sha256.Sum256(raw); hex.EncodeToString(id[:]) != nodeTxID {
		t.Fatalf("txID = %x, want %s", id, nodeTxID)
	}
}
