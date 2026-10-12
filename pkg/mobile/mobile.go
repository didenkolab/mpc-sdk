// Package mobile exposes the DKLs23 protocol, address derivation and Tron
// transaction building through a gomobile-compatible API: only strings,
// numbers, booleans and simple structs cross the boundary, and lists are
// passed as JSON arrays.
//
// Build for Android:
//
//	gomobile bind -target=android -o mpc-sdk.aar github.com/didenkolab/mpc-sdk/pkg/mobile
//
// The Rust FFI library must first be compiled for the Android targets.
package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/didenkolab/mpc-sdk/pkg/chain/tron"
	"github.com/didenkolab/mpc-sdk/pkg/dkls23"
)

// ============ DKG ============

// DKLS23DKGState is one party's DKLs23 key generation state.
type DKLS23DKGState struct {
	state *dkls23.DKGState
}

// NewDKLS23DKGState creates a key generation state for partyID (0-based) of a
// threshold-of-nParties key.
func NewDKLS23DKGState(partyID int, nParties int, threshold int) (*DKLS23DKGState, error) {
	if partyID < 0 || partyID > 255 {
		return nil, dkls23.ErrInvalidPartyID
	}
	state, err := dkls23.NewDKGState(uint8(partyID), nParties, threshold)
	if err != nil {
		return nil, err
	}
	return &DKLS23DKGState{state: state}, nil
}

// GenerateMsg1 returns the round-1 message to broadcast.
func (s *DKLS23DKGState) GenerateMsg1() (string, error) {
	return s.state.GenerateMsg1()
}

// HandleMsg1 takes a JSON array of the other parties' msg1 and returns a JSON
// array of point-to-point msg2 (route each element by its "to_id").
func (s *DKLS23DKGState) HandleMsg1(msgsJSON string) (string, error) {
	msgs, err := decodeArray(msgsJSON)
	if err != nil {
		return "", err
	}
	return s.state.HandleMsg1(msgs)
}

// HandleMsg2 takes a JSON array of the msg2 addressed to this party and
// returns a JSON array of point-to-point msg3.
func (s *DKLS23DKGState) HandleMsg2(msgsJSON string) (string, error) {
	msgs, err := decodeArray(msgsJSON)
	if err != nil {
		return "", err
	}
	return s.state.HandleMsg2(msgs)
}

// CalculateCommitment2 returns this party's commitment, needed by every party
// in HandleMsg3.
func (s *DKLS23DKGState) CalculateCommitment2() (string, error) {
	return s.state.CalculateCommitment2()
}

// HandleMsg3 takes a JSON array of the msg3 addressed to this party and a JSON
// array of all commitments ordered by party ID, and returns the msg4 to
// broadcast.
func (s *DKLS23DKGState) HandleMsg3(msgsJSON string, commitmentsJSON string) (string, error) {
	msgs, err := decodeArray(msgsJSON)
	if err != nil {
		return "", err
	}
	var commits []string
	if err := json.Unmarshal([]byte(commitmentsJSON), &commits); err != nil {
		return "", fmt.Errorf("commitments must be a JSON array of strings: %w", err)
	}
	return s.state.HandleMsg3(msgs, commits)
}

// HandleMsg4 takes a JSON array of the other parties' msg4 and returns the
// keyshare JSON.
func (s *DKLS23DKGState) HandleMsg4(msgsJSON string) (string, error) {
	msgs, err := decodeArray(msgsJSON)
	if err != nil {
		return "", err
	}
	return s.state.HandleMsg4(msgs)
}

// Free releases the native state. It is safe to call more than once.
func (s *DKLS23DKGState) Free() {
	if s.state != nil {
		s.state.Free()
		s.state = nil
	}
}

// ============ DSG (signing) ============

// DKLS23DSGState is one party's DKLs23 signing state.
type DKLS23DSGState struct {
	state *dkls23.DSGState
}

// NewDKLS23DSGState creates a signing state for the BIP32 child of
// keyshareJSON at derivationPath ("m" for the root key).
func NewDKLS23DSGState(keyshareJSON string, derivationPath string) (*DKLS23DSGState, error) {
	state, err := dkls23.NewDSGState(keyshareJSON, derivationPath)
	if err != nil {
		return nil, err
	}
	return &DKLS23DSGState{state: state}, nil
}

// GenerateMsg1 returns the round-1 message to broadcast.
func (s *DKLS23DSGState) GenerateMsg1() (string, error) {
	return s.state.GenerateMsg1()
}

// HandleMsg1 takes a JSON array of the other signers' msg1 and returns a JSON
// array of point-to-point msg2.
func (s *DKLS23DSGState) HandleMsg1(msgsJSON string) (string, error) {
	msgs, err := decodeArray(msgsJSON)
	if err != nil {
		return "", err
	}
	return s.state.HandleMsg1(msgs)
}

// HandleMsg2 takes a JSON array of the msg2 addressed to this signer and
// returns a JSON array of point-to-point msg3.
func (s *DKLS23DSGState) HandleMsg2(msgsJSON string) (string, error) {
	msgs, err := decodeArray(msgsJSON)
	if err != nil {
		return "", err
	}
	return s.state.HandleMsg2(msgs)
}

// HandleMsg3 takes a JSON array of the msg3 addressed to this signer and
// returns a single-use presignature handle.
func (s *DKLS23DSGState) HandleMsg3(msgsJSON string) (string, error) {
	msgs, err := decodeArray(msgsJSON)
	if err != nil {
		return "", err
	}
	return s.state.HandleMsg3(msgs)
}

// Free releases the native state. It is safe to call more than once.
func (s *DKLS23DSGState) Free() {
	if s.state != nil {
		s.state.Free()
		s.state = nil
	}
}

// ============ Signatures ============

// DKLS23CreatePartialSignature signs a 32-byte message hash, given as 64 hex
// characters with an optional 0x prefix, with a presignature handle. It
// returns {"partial": ..., "msg4": ...}. The presignature is consumed.
func DKLS23CreatePartialSignature(presigJSON string, messageHashHex string) (string, error) {
	hashBytes, err := hexDecode(messageHashHex)
	if err != nil {
		return "", fmt.Errorf("message hash: %w", err)
	}
	var hash [32]byte
	if len(hashBytes) != len(hash) {
		return "", fmt.Errorf("message hash must be 32 bytes, got %d", len(hashBytes))
	}
	copy(hash[:], hashBytes)
	return dkls23.CreatePartialSignature(presigJSON, hash)
}

// DKLS23CombineSignatures combines the local "partial" with a JSON array of
// the other signers' "msg4" values and returns the hex signature r || s.
func DKLS23CombineSignatures(partialSigJSON string, msg4JSON string) (string, error) {
	msg4List, err := decodeArray(msg4JSON)
	if err != nil {
		return "", err
	}
	return dkls23.CombineSignatures(partialSigJSON, msg4List)
}

// ============ Key derivation ============

// DKLS23DerivePublicKey returns {"derived_public_key": "<hex>"} for the BIP32
// child at derivationPath.
func DKLS23DerivePublicKey(keyshareJSON string, derivationPath string) (string, error) {
	return dkls23.DerivePublicKey(keyshareJSON, derivationPath)
}

// DKLS23DeriveKeyshare returns the keyshare of the BIP32 child at
// derivationPath; sign with it using path "m".
func DKLS23DeriveKeyshare(keyshareJSON string, derivationPath string) (string, error) {
	return dkls23.DeriveKeyshare(keyshareJSON, derivationPath)
}

// ============ Addresses ============

// PublicKeyToEthereumAddress converts a hex secp256k1 public key to a
// lowercase 0x-prefixed Ethereum address.
func PublicKeyToEthereumAddress(publicKeyHex string) (string, error) {
	return dkls23.PublicKeyToEthereumAddress(publicKeyHex)
}

// PublicKeyToBitcoinAddress converts a hex secp256k1 public key to a P2PKH
// address.
func PublicKeyToBitcoinAddress(publicKeyHex string, mainnet bool) (string, error) {
	return dkls23.PublicKeyToBitcoinAddress(publicKeyHex, mainnet)
}

// PublicKeyToBitcoinSegWitAddress converts a hex secp256k1 public key to a
// P2WPKH (Bech32) address.
func PublicKeyToBitcoinSegWitAddress(publicKeyHex string, mainnet bool) (string, error) {
	return dkls23.PublicKeyToBitcoinSegWitAddress(publicKeyHex, mainnet)
}

// PublicKeyToTronAddress converts a hex compressed secp256k1 public key to a
// Base58Check Tron address.
func PublicKeyToTronAddress(publicKeyHex string) (string, error) {
	pubKeyBytes, err := hexDecode(publicKeyHex)
	if err != nil {
		return "", err
	}
	return tron.DeriveAddress(pubKeyBytes)
}

// ============ Tron transactions ============

// TronRawTxResult is the result of building a Tron transaction. It is
// returned as JSON with the keys "RawDataHex", "TxID" and "MessageHash".
type TronRawTxResult struct {
	RawDataHex  string // hex-encoded protobuf raw_data
	TxID        string // hex SHA-256(raw_data), the transaction ID
	MessageHash string // same as TxID: the 32-byte hash to sign
}

// Placeholder reference block used by BuildTronTransaction.
const (
	placeholderRefBlockBytes = "0d3a"
	placeholderRefBlockHash  = "8fa9e75800000000"
)

// BuildTronTransaction builds an unsigned TRX transfer of amountSun
// (1 TRX = 1,000,000 SUN) that expires in one hour.
//
// It uses a fixed placeholder reference block, so the network rejects the
// result; it is meant for testing the signing flow. Use
// BuildTronTransactionWithRefBlock with data from a recent block for real
// transfers.
func BuildTronTransaction(fromAddress, toAddress string, amountSun int64) (string, error) {
	now := time.Now()
	return BuildTronTransactionWithRefBlock(
		fromAddress, toAddress, amountSun,
		placeholderRefBlockBytes, placeholderRefBlockHash,
		now.Add(time.Hour).UnixMilli(), now.UnixMilli(),
	)
}

// BuildTronTransactionWithRefBlock builds an unsigned TRX transfer.
// refBlockBytesHex is bytes 6..8 of a recent block number (4 hex chars) and
// refBlockHashHex bytes 8..16 of its hash (16 hex chars); expirationMs and
// timestampMs are Unix milliseconds. The result is a TronRawTxResult as JSON.
func BuildTronTransactionWithRefBlock(fromAddress, toAddress string, amountSun int64,
	refBlockBytesHex, refBlockHashHex string, expirationMs, timestampMs int64) (string, error) {
	if amountSun <= 0 {
		return "", errors.New("amount must be positive")
	}
	if expirationMs <= timestampMs {
		return "", errors.New("expiration must be after timestamp")
	}

	_, rawData, err := tron.BuildTRXTransfer(
		fromAddress,
		toAddress,
		uint64(amountSun),
		refBlockBytesHex,
		refBlockHashHex,
		expirationMs,
		timestampMs,
	)
	if err != nil {
		return "", err
	}

	rawHash := sha256.Sum256(rawData)
	txID := hex.EncodeToString(rawHash[:])
	out, err := json.Marshal(TronRawTxResult{
		RawDataHex:  hex.EncodeToString(rawData),
		TxID:        txID,
		MessageHash: txID,
	})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ============ Helpers ============

// decodeArray parses a JSON array, keeping each element as raw JSON.
func decodeArray(s string) ([]interface{}, error) {
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(s), &items); err != nil {
		return nil, fmt.Errorf("expected a JSON array: %w", err)
	}
	out := make([]interface{}, len(items))
	for i, item := range items {
		out[i] = item
	}
	return out, nil
}

// hexDecode decodes a hex string with an optional 0x prefix.
func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	return hex.DecodeString(s)
}
