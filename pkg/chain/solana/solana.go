package solana

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/blocto/solana-go-sdk/common"
	solanatypes "github.com/blocto/solana-go-sdk/types"
	"github.com/didenkolab/mpc-sdk/pkg/frost"
)

// MessageHash returns the SHA-256 digest of the serialized message together
// with the serialized bytes. Note that Solana signatures are Ed25519 over the
// serialized message itself, not over this digest; sign raw instead.
func MessageHash(msg solanatypes.Message) ([32]byte, []byte, error) {
	raw, err := msg.Serialize()
	if err != nil {
		return [32]byte{}, nil, err
	}
	return sha256.Sum256(raw), raw, nil
}

// AssembleTransaction attaches the fee payer's Ed25519 signature to msg.
// The signature must be 64 bytes and valid for pub over the serialized
// message.
func AssembleTransaction(msg solanatypes.Message, sig []byte, pub common.PublicKey) (solanatypes.Transaction, error) {
	if len(sig) != ed25519.SignatureSize {
		return solanatypes.Transaction{}, errors.New("signature must be 64 bytes")
	}
	raw, err := msg.Serialize()
	if err != nil {
		return solanatypes.Transaction{}, fmt.Errorf("serialize message: %w", err)
	}
	if !ed25519.Verify(pub.Bytes(), raw, sig) {
		return solanatypes.Transaction{}, errors.New("signature is not valid for the public key and message")
	}
	tx := solanatypes.Transaction{
		Signatures: []solanatypes.Signature{sig},
		Message:    msg,
	}
	return tx, nil
}

// PubKeyFromHex converts 32-byte hex string to solana.PublicKey.
func PubKeyFromHex(h string) (common.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return common.PublicKey{}, err
	}
	if len(b) != 32 {
		return common.PublicKey{}, errors.New("public key must be 32 bytes")
	}
	return common.PublicKeyFromBytes(b), nil
}

// DeriveAddress creates a Solana address from Ed25519 public key bytes.
func DeriveAddress(ed25519PubKey []byte) (common.PublicKey, error) {
	if len(ed25519PubKey) != 32 {
		return common.PublicKey{}, errors.New("ed25519 public key must be 32 bytes")
	}
	return common.PublicKeyFromBytes(ed25519PubKey), nil
}

// BuildTransferSOL creates a SOL transfer transaction.
func BuildTransferSOL(from, to common.PublicKey, amount uint64, recentBlockhash string) (solanatypes.Message, error) {
	instruction := solanatypes.Instruction{
		ProgramID: common.SystemProgramID,
		Accounts: []solanatypes.AccountMeta{
			{PubKey: from, IsSigner: true, IsWritable: true},
			{PubKey: to, IsSigner: false, IsWritable: true},
		},
		Data: buildTransferInstruction(amount),
	}

	message := solanatypes.NewMessage(solanatypes.NewMessageParam{
		FeePayer:        from,
		RecentBlockhash: recentBlockhash,
		Instructions:    []solanatypes.Instruction{instruction},
	})

	return message, nil
}

// BuildSPLTokenTransfer creates an SPL token transfer transaction.
func BuildSPLTokenTransfer(from, to common.PublicKey, fromTokenAccount, toTokenAccount,
	tokenMint common.PublicKey, amount uint64, decimals uint8, recentBlockhash string) (solanatypes.Message, error) {

	// SPL Token transfer instruction
	instruction := solanatypes.Instruction{
		ProgramID: common.TokenProgramID,
		Accounts: []solanatypes.AccountMeta{
			{PubKey: fromTokenAccount, IsSigner: false, IsWritable: true}, // source
			{PubKey: toTokenAccount, IsSigner: false, IsWritable: true},   // destination
			{PubKey: from, IsSigner: true, IsWritable: false},             // authority
		},
		Data: buildSPLTransferInstruction(amount),
	}

	message := solanatypes.NewMessage(solanatypes.NewMessageParam{
		FeePayer:        from,
		RecentBlockhash: recentBlockhash,
		Instructions:    []solanatypes.Instruction{instruction},
	})

	return message, nil
}

// BuildCreateAccount creates an account creation transaction.
func BuildCreateAccount(payer, newAccount common.PublicKey, lamports uint64,
	space uint64, owner common.PublicKey, recentBlockhash string) (solanatypes.Message, error) {

	instruction := solanatypes.Instruction{
		ProgramID: common.SystemProgramID,
		Accounts: []solanatypes.AccountMeta{
			{PubKey: payer, IsSigner: true, IsWritable: true},
			{PubKey: newAccount, IsSigner: true, IsWritable: true},
		},
		Data: buildCreateAccountInstruction(lamports, space, owner),
	}

	message := solanatypes.NewMessage(solanatypes.NewMessageParam{
		FeePayer:        payer,
		RecentBlockhash: recentBlockhash,
		Instructions:    []solanatypes.Instruction{instruction},
	})

	return message, nil
}

// buildTransferInstruction builds a system transfer instruction data.
func buildTransferInstruction(amount uint64) []byte {
	// System program transfer instruction: [2, 0, 0, 0] + amount (8 bytes LE)
	data := make([]byte, 12)
	data[0] = 2 // Transfer instruction index

	// Amount in little endian
	for i := 0; i < 8; i++ {
		data[4+i] = byte(amount >> (8 * i))
	}

	return data
}

// buildSPLTransferInstruction builds an SPL token transfer instruction data.
func buildSPLTransferInstruction(amount uint64) []byte {
	// SPL Token transfer instruction: [3] + amount (8 bytes LE)
	data := make([]byte, 9)
	data[0] = 3 // Transfer instruction index

	// Amount in little endian
	for i := 0; i < 8; i++ {
		data[1+i] = byte(amount >> (8 * i))
	}

	return data
}

// buildCreateAccountInstruction builds a create account instruction data.
func buildCreateAccountInstruction(lamports, space uint64, owner common.PublicKey) []byte {
	// Create account instruction: [0, 0, 0, 0] + lamports (8 bytes LE) + space (8 bytes LE) + owner (32 bytes)
	data := make([]byte, 52)
	data[0] = 0 // Create account instruction index

	// Lamports in little endian
	for i := 0; i < 8; i++ {
		data[4+i] = byte(lamports >> (8 * i))
	}

	// Space in little endian
	for i := 0; i < 8; i++ {
		data[12+i] = byte(space >> (8 * i))
	}

	// Owner program ID
	copy(data[20:], owner[:])

	return data
}

// DeriveAssociatedTokenAccount derives the associated token account address.
func DeriveAssociatedTokenAccount(wallet, mint common.PublicKey) (common.PublicKey, error) {
	ata, _, err := common.FindAssociatedTokenAddress(wallet, mint)
	return ata, err
}

// SignMessage signs a Solana message with a single Ed25519 private key (non-threshold).
// For threshold signing use SignMessageWithFROST.
func SignMessage(message solanatypes.Message, privateKey []byte) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: got %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}

	raw, err := message.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize message: %w", err)
	}

	sig := ed25519.Sign(privateKey, raw)
	return sig, nil
}

// SignMessageWithFROST signs a Solana message with FROST threshold Ed25519,
// running all rounds in-process with the first threshold keyshares. It is
// intended for tests and single-process setups; distributed deployments run
// the rounds through their own transport.
//
// The serialized message itself is signed, as Solana requires.
func SignMessageWithFROST(message solanatypes.Message, keyShares []string, threshold int) ([]byte, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if len(keyShares) < threshold {
		return nil, errors.New("insufficient key shares for threshold signing")
	}

	raw, err := message.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize message: %w", err)
	}

	signers := make([]*frost.SigningState, 0, threshold)
	defer func() {
		for _, s := range signers {
			s.Free()
		}
	}()
	for i := 0; i < threshold; i++ {
		s, err := frost.NewSigningStateForMessage(keyShares[i], raw)
		if err != nil {
			return nil, fmt.Errorf("create signing state for keyshare %d: %w", i, err)
		}
		signers = append(signers, s)
	}

	// Round 1: nonce commitments.
	commitments := make([]string, len(signers))
	for i, s := range signers {
		if commitments[i], err = s.GenerateMsg1(); err != nil {
			return nil, fmt.Errorf("generate commitments for signer %d: %w", i, err)
		}
	}

	// Round 2: signature shares.
	shares := make([]interface{}, len(signers))
	for i, s := range signers {
		others := make([]interface{}, 0, len(signers)-1)
		for j, c := range commitments {
			if j != i {
				others = append(others, c)
			}
		}
		share, err := s.HandleMsg1(others)
		if err != nil {
			return nil, fmt.Errorf("compute signature share for signer %d: %w", i, err)
		}
		shares[i] = share
	}

	sigHex, err := frost.CombineSignatures(shares[0].(string), shares[1:])
	if err != nil {
		return nil, fmt.Errorf("combine signatures: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	return sig, nil
}
