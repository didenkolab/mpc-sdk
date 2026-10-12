package threshold

import (
	"errors"
	"fmt"
)

// SignatureAlgorithm selects the threshold signature scheme.
type SignatureAlgorithm int

const (
	// Ed25519FROST is Ed25519 Schnorr signing with the FROST protocol
	// (Solana, NEAR).
	Ed25519FROST SignatureAlgorithm = iota
	// ECDSASecp256k1 is ECDSA over secp256k1 with the DKLs23 protocol
	// (Bitcoin, Ethereum and other EVM chains, Tron).
	ECDSASecp256k1
)

// ExecutionMode controls whether all parties may be simulated locally.
type ExecutionMode int

const (
	// ExecutionModeProd runs a single local party; the other parties are
	// reached through a MessageTransport.
	ExecutionModeProd ExecutionMode = iota
	// ExecutionModeInMemoryDemo runs every party in the current process. It
	// is intended for tests and demos only: one process holds all keyshares.
	ExecutionModeInMemoryDemo
)

// String returns a human-readable algorithm name.
func (a SignatureAlgorithm) String() string {
	switch a {
	case Ed25519FROST:
		return "Ed25519-FROST"
	case ECDSASecp256k1:
		return "ECDSA-Secp256k1-DKLs23"
	default:
		return fmt.Sprintf("Unknown-%d", int(a))
	}
}

// ThresholdConfig describes a t-of-n key generation.
type ThresholdConfig struct {
	Algorithm    SignatureAlgorithm `json:"algorithm"`
	Participants int                `json:"participants"` // total number of parties (n)
	Threshold    int                `json:"threshold"`    // parties required to sign (t)
	PartyID      uint8              `json:"party_id"`     // 0-based ID of the local party
	Mode         ExecutionMode      `json:"-"`
	SessionID    string             `json:"-"` // shared by all parties (prod mode)
	Transport    MessageTransport   `json:"-"` // required in prod mode
}

// Validate reports whether the configuration is usable.
func (c *ThresholdConfig) Validate() error {
	if c.Participants < 2 {
		return fmt.Errorf("participants must be >= 2, got %d", c.Participants)
	}
	if c.Participants > maxParties {
		return fmt.Errorf("participants must be <= %d, got %d", maxParties, c.Participants)
	}
	if c.Threshold < 1 {
		return fmt.Errorf("threshold must be >= 1, got %d", c.Threshold)
	}
	if c.Threshold > c.Participants {
		return fmt.Errorf("threshold (%d) cannot exceed participants (%d)",
			c.Threshold, c.Participants)
	}
	if int(c.PartyID) >= c.Participants {
		return fmt.Errorf("party_id (%d) must be < participants (%d)",
			c.PartyID, c.Participants)
	}
	if c.Mode == ExecutionModeProd {
		if c.SessionID == "" {
			return errors.New("session_id is required in prod mode to coordinate parties over transport")
		}
		if c.Transport == nil {
			return errors.New("transport is required in prod mode")
		}
	}
	return nil
}

// KeyShare is one party's share of a threshold key.
type KeyShare struct {
	Algorithm    SignatureAlgorithm `json:"algorithm"`
	PartyID      uint8              `json:"party_id"`
	Participants int                `json:"participants"`
	Threshold    int                `json:"threshold"`
	KeyData      string             `json:"key_data"`   // protocol keyshare JSON (secret)
	PublicKey    string             `json:"public_key"` // hex public key for Path
	// Path is the BIP32 path (from the root key) that KeyData signs for.
	// Empty means the root key ("m").
	Path string `json:"derivation_path,omitempty"`
}

// Signature is a threshold signature.
type Signature struct {
	Algorithm SignatureAlgorithm `json:"algorithm"`
	// Data is the raw signature: r || s (64 bytes) for ECDSA, or the 64-byte
	// Ed25519 signature for FROST.
	Data      []byte `json:"data"`
	R         string `json:"r,omitempty"` // hex, ECDSA only
	S         string `json:"s,omitempty"` // hex, ECDSA only
	PublicKey string `json:"public_key"`  // hex public key that verifies the signature
}

// BusinessOperation is implemented by each threshold protocol.
type BusinessOperation interface {
	// GetAlgorithm returns the protocol's algorithm.
	GetAlgorithm() SignatureAlgorithm

	// GenerateThresholdKeys runs distributed key generation. In prod mode it
	// returns only the local party's share; in demo mode it returns all shares.
	GenerateThresholdKeys(config *ThresholdConfig) ([]*KeyShare, error)

	// SignMessage signs SHA-256(message) with the shares at signerIndices.
	SignMessage(message []byte, keyShares []*KeyShare, signerIndices []int) (*Signature, error)

	// VerifySignature verifies a signature produced by SignMessage.
	VerifySignature(message []byte, signature *Signature) (bool, error)

	// DeriveChildKey returns the share for the child key at derivationPath.
	DeriveChildKey(keyShare *KeyShare, derivationPath string) (*KeyShare, error)
}

// WalletAddress is a blockchain address derived from a public key.
type WalletAddress struct {
	Algorithm SignatureAlgorithm `json:"algorithm"`
	Address   string             `json:"address"`
	PublicKey string             `json:"public_key"`
	Path      string             `json:"derivation_path,omitempty"`
}

// BusinessWallet adds wallet operations to BusinessOperation.
type BusinessWallet interface {
	BusinessOperation

	// GenerateAddress derives an address of the given type for keyShare.
	GenerateAddress(keyShare *KeyShare, addressType string) (*WalletAddress, error)

	// SignTransaction signs a 32-byte transaction digest as-is.
	SignTransaction(txHash []byte, keyShares []*KeyShare, signerIndices []int,
		fromAddress *WalletAddress) (*Signature, error)

	// GetBalance returns the balance of address.
	GetBalance(address *WalletAddress) (string, error)
}

// BalanceProvider supplies balances from a blockchain backend.
type BalanceProvider interface {
	Balance(address *WalletAddress) (string, error)
}

// digestOperation is implemented by protocols that can sign and verify a
// precomputed 32-byte digest without hashing it again.
type digestOperation interface {
	signDigest(digest [32]byte, keyShares []*KeyShare, signerIndices []int) (*Signature, error)
	verifyDigest(digest [32]byte, signature *Signature) (bool, error)
}

// maxParties is the largest party count addressable with 8-bit party IDs.
const maxParties = 255
