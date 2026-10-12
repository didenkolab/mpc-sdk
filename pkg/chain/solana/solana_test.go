package solana

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/blocto/solana-go-sdk/common"
	"github.com/blocto/solana-go-sdk/program/system"
	"github.com/blocto/solana-go-sdk/types"

	"github.com/didenkolab/mpc-sdk/pkg/frost"
)

func TestMessageHash(t *testing.T) {
	from := common.PublicKeyFromString(common.SystemProgramID.ToBase58())
	to := common.PublicKeyFromString("11111111111111111111111111111111")
	msg := types.NewMessage(types.NewMessageParam{
		FeePayer:        from,
		RecentBlockhash: "11111111111111111111111111111111",
		Instructions: []types.Instruction{
			system.Transfer(system.TransferParam{From: from, To: to, Amount: 1}),
		},
	})
	hash, raw, err := MessageHash(msg)
	if err != nil {
		t.Fatalf("message hash err: %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("empty serialized message")
	}
	if hash != sha256.Sum256(raw) {
		t.Fatalf("hash must be SHA-256 of the serialized message")
	}
}

func TestDeriveAddress(t *testing.T) {
	// Test with valid 32-byte Ed25519 public key
	pubKey := make([]byte, 32)
	for i := range pubKey {
		pubKey[i] = byte(i)
	}

	addr, err := DeriveAddress(pubKey)
	if err != nil {
		t.Fatalf("derive address error: %v", err)
	}

	// Verify the address is valid
	addrStr := addr.ToBase58()
	if len(addrStr) == 0 {
		t.Fatalf("empty address string")
	}

	// Test with invalid length
	_, err = DeriveAddress([]byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid pubkey length")
	}
}

func TestPubKeyFromHex(t *testing.T) {
	// Test with valid 32-byte hex
	hexStr := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	pubKey, err := PubKeyFromHex(hexStr)
	if err != nil {
		t.Fatalf("pubkey from hex error: %v", err)
	}

	addrStr := pubKey.ToBase58()
	if len(addrStr) == 0 {
		t.Fatalf("empty address string")
	}

	// Test with invalid hex
	_, err = PubKeyFromHex("invalid")
	if err == nil {
		t.Fatalf("expected error for invalid hex")
	}

	// Test with wrong length
	_, err = PubKeyFromHex("0123")
	if err == nil {
		t.Fatalf("expected error for wrong length")
	}
}

func TestBuildTransferSOL(t *testing.T) {
	from := common.PublicKeyFromString("11111111111111111111111111111111")
	to := common.PublicKeyFromString("22222222222222222222222222222222")
	amount := uint64(1000000000) // 1 SOL in lamports
	recentBlockhash := "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"

	msg, err := BuildTransferSOL(from, to, amount, recentBlockhash)
	if err != nil {
		t.Fatalf("build transfer SOL: %v", err)
	}

	// Check message structure - ensure it's valid
	if msg.RecentBlockHash == "" {
		t.Fatalf("expected recent blockhash in message")
	}

	if len(msg.Instructions) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(msg.Instructions))
	}

	instruction := msg.Instructions[0]
	if instruction.ProgramIDIndex != 0 { // System program should be first
		t.Fatalf("expected system program as instruction program")
	}

	// Check instruction data length (should be 12 bytes for transfer)
	if len(instruction.Data) != 12 {
		t.Fatalf("expected 12 bytes instruction data, got %d", len(instruction.Data))
	}

	// Check instruction type (should be 2 for transfer)
	if instruction.Data[0] != 2 {
		t.Fatalf("expected transfer instruction type 2, got %d", instruction.Data[0])
	}
}

func TestBuildSPLTokenTransfer(t *testing.T) {
	from := common.PublicKeyFromString("11111111111111111111111111111111")
	to := common.PublicKeyFromString("22222222222222222222222222222222")
	fromTokenAccount := common.PublicKeyFromString("33333333333333333333333333333333")
	toTokenAccount := common.PublicKeyFromString("44444444444444444444444444444444")
	tokenMint := common.PublicKeyFromString("55555555555555555555555555555555")
	amount := uint64(1000000) // 1 token (assuming 6 decimals)
	decimals := uint8(6)
	recentBlockhash := "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"

	msg, err := BuildSPLTokenTransfer(from, to, fromTokenAccount, toTokenAccount,
		tokenMint, amount, decimals, recentBlockhash)
	if err != nil {
		t.Fatalf("build SPL token transfer: %v", err)
	}

	// Check message structure
	if len(msg.Instructions) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(msg.Instructions))
	}

	instruction := msg.Instructions[0]

	// Check instruction data length (should be 9 bytes for SPL transfer)
	if len(instruction.Data) != 9 {
		t.Fatalf("expected 9 bytes instruction data, got %d", len(instruction.Data))
	}

	// Check instruction type (should be 3 for SPL transfer)
	if instruction.Data[0] != 3 {
		t.Fatalf("expected SPL transfer instruction type 3, got %d", instruction.Data[0])
	}
}

func TestBuildCreateAccount(t *testing.T) {
	payer := common.PublicKeyFromString("11111111111111111111111111111111")
	newAccount := common.PublicKeyFromString("22222222222222222222222222222222")
	owner := common.TokenProgramID
	lamports := uint64(2039280) // rent exempt amount for token account
	space := uint64(165)        // space for token account
	recentBlockhash := "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"

	msg, err := BuildCreateAccount(payer, newAccount, lamports, space, owner, recentBlockhash)
	if err != nil {
		t.Fatalf("build create account: %v", err)
	}

	// Check message structure
	if len(msg.Instructions) != 1 {
		t.Fatalf("expected 1 instruction, got %d", len(msg.Instructions))
	}

	instruction := msg.Instructions[0]

	// Check instruction data length (should be 52 bytes for create account)
	if len(instruction.Data) != 52 {
		t.Fatalf("expected 52 bytes instruction data, got %d", len(instruction.Data))
	}

	// Check instruction type (should be 0 for create account)
	if instruction.Data[0] != 0 {
		t.Fatalf("expected create account instruction type 0, got %d", instruction.Data[0])
	}
}

func TestAssembleTransaction(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	from := common.PublicKeyFromBytes(pub)
	to := common.PublicKeyFromString("22222222222222222222222222222222")
	msg, err := BuildTransferSOL(from, to, 1000000000, "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignMessage(msg, priv)
	if err != nil {
		t.Fatal(err)
	}

	tx, err := AssembleTransaction(msg, sig, from)
	if err != nil {
		t.Fatalf("assemble transaction: %v", err)
	}
	if len(tx.Signatures) != 1 || !bytes.Equal(tx.Signatures[0], sig) {
		t.Fatalf("unexpected signatures: %x", tx.Signatures)
	}
	if _, err := tx.Serialize(); err != nil {
		t.Fatalf("serialize transaction: %v", err)
	}

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	errCases := map[string][]byte{
		"short signature":   {0x01, 0x02},
		"invalid signature": tampered,
	}
	for name, bad := range errCases {
		if _, err := AssembleTransaction(msg, bad, from); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := AssembleTransaction(msg, sig, to); err == nil {
		t.Error("wrong public key: expected error")
	}
}

func TestDeriveAssociatedTokenAccount(t *testing.T) {
	wallet := common.PublicKeyFromString("11111111111111111111111111111111")
	mint := common.PublicKeyFromString("22222222222222222222222222222222")

	ata, err := DeriveAssociatedTokenAccount(wallet, mint)
	if err != nil {
		t.Fatalf("derive associated token account: %v", err)
	}

	// Verify the result is a valid public key
	ataStr := ata.ToBase58()
	if len(ataStr) == 0 {
		t.Fatalf("empty ATA address")
	}

	// Test deterministic derivation
	ata2, err := DeriveAssociatedTokenAccount(wallet, mint)
	if err != nil {
		t.Fatalf("derive ATA second time: %v", err)
	}

	if ata.ToBase58() != ata2.ToBase58() {
		t.Fatalf("ATA derivation should be deterministic")
	}
}

func TestSignMessage(t *testing.T) {
	from := common.PublicKeyFromString("11111111111111111111111111111111")
	to := common.PublicKeyFromString("22222222222222222222222222222222")
	msg, _ := BuildTransferSOL(from, to, 1000000000, "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")

	// Create dummy 64-byte private key
	privateKey := make([]byte, 64)
	for i := range privateKey {
		privateKey[i] = byte(i % 256)
	}

	sig, err := SignMessage(msg, privateKey)
	if err != nil {
		t.Fatalf("sign message: %v", err)
	}

	if len(sig) != 64 {
		t.Fatalf("expected 64-byte signature, got %d bytes", len(sig))
	}

	// Test with invalid private key length
	_, err = SignMessage(msg, []byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for invalid private key length")
	}
}

func TestBuildTransferInstruction(t *testing.T) {
	amount := uint64(1000000000) // 1 SOL
	data := buildTransferInstruction(amount)

	if len(data) != 12 {
		t.Fatalf("expected 12 bytes instruction data, got %d", len(data))
	}

	// Check instruction type
	if data[0] != 2 {
		t.Fatalf("expected instruction type 2, got %d", data[0])
	}

	// Verify amount encoding (little endian)
	var decodedAmount uint64
	for i := 0; i < 8; i++ {
		decodedAmount |= uint64(data[4+i]) << (8 * i)
	}

	if decodedAmount != amount {
		t.Fatalf("amount encoding error: got %d, expected %d", decodedAmount, amount)
	}
}

func TestBuildSPLTransferInstruction(t *testing.T) {
	amount := uint64(1000000) // 1 token
	data := buildSPLTransferInstruction(amount)

	if len(data) != 9 {
		t.Fatalf("expected 9 bytes instruction data, got %d", len(data))
	}

	// Check instruction type
	if data[0] != 3 {
		t.Fatalf("expected instruction type 3, got %d", data[0])
	}

	// Verify amount encoding (little endian)
	var decodedAmount uint64
	for i := 0; i < 8; i++ {
		decodedAmount |= uint64(data[1+i]) << (8 * i)
	}

	if decodedAmount != amount {
		t.Fatalf("amount encoding error: got %d, expected %d", decodedAmount, amount)
	}
}

// frostKeyshares runs an in-process FROST DKG and returns all keyshares.
func frostKeyshares(t *testing.T, n, threshold int) []string {
	t.Helper()
	states := make([]*frost.DKGState, n)
	msg1 := make([]string, n)
	for i := range states {
		s, err := frost.NewDKGState(uint8(i+1), n, threshold)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Free)
		states[i] = s
		if msg1[i], err = s.GenerateMsg1(); err != nil {
			t.Fatal(err)
		}
	}
	others := func(msgs []string, self int) []interface{} {
		var out []interface{}
		for j, m := range msgs {
			if j != self {
				out = append(out, m)
			}
		}
		return out
	}
	msg2 := make([]string, n)
	for i, s := range states {
		var err error
		if msg2[i], err = s.HandleMsg1(others(msg1, i)); err != nil {
			t.Fatal(err)
		}
	}
	keyshares := make([]string, n)
	for i, s := range states {
		in, err := frost.Round2MessagesFor(uint8(i+1), msg2...)
		if err != nil {
			t.Fatal(err)
		}
		if keyshares[i], err = s.HandleMsg2(in); err != nil {
			t.Fatal(err)
		}
	}
	return keyshares
}

func TestSignMessageWithFROST(t *testing.T) {
	keyshares := frostKeyshares(t, 3, 2)

	pubJSON, err := frost.DerivePublicKey(keyshares[0], "m")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		DerivedPublicKey string `json:"derived_public_key"`
	}
	if err := json.Unmarshal([]byte(pubJSON), &parsed); err != nil {
		t.Fatal(err)
	}
	from, err := PubKeyFromHex(parsed.DerivedPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	to := common.PublicKeyFromString("22222222222222222222222222222222")
	msg, err := BuildTransferSOL(from, to, 5000, "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N")
	if err != nil {
		t.Fatal(err)
	}

	for _, subset := range [][]string{keyshares[:2], {keyshares[1], keyshares[2]}} {
		sig, err := SignMessageWithFROST(msg, subset, 2)
		if err != nil {
			t.Fatalf("SignMessageWithFROST: %v", err)
		}
		raw, err := msg.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(from.Bytes(), raw, sig) {
			t.Fatal("threshold signature does not verify over the serialized message")
		}
		if _, err := AssembleTransaction(msg, sig, from); err != nil {
			t.Fatalf("AssembleTransaction: %v", err)
		}
	}

	errCases := []struct {
		name      string
		keyshares []string
		threshold int
	}{
		{"threshold below 2", keyshares, 1},
		{"not enough keyshares", keyshares[:1], 2},
		{"malformed keyshare", []string{"{}", keyshares[1]}, 2},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SignMessageWithFROST(msg, tc.keyshares, tc.threshold); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
