// Package threshold is a high-level API over the DKLs23 (threshold ECDSA,
// secp256k1) and FROST (threshold Ed25519) protocols.
//
// A WalletManager generates threshold keys, derives addresses and signs
// messages or transaction digests. It runs in one of two modes:
//
//   - ExecutionModeProd: the local process is a single party. Key generation
//     exchanges messages with the other parties through a MessageTransport
//     and returns only the local keyshare.
//   - ExecutionModeInMemoryDemo: every party runs in the current process.
//     This is convenient for tests and demos but places all keyshares in one
//     process, which defeats the purpose of threshold cryptography.
//
// For multi-process key generation use DKGSession directly.
package threshold

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/mr-tron/base58"

	"github.com/didenkolab/mpc-sdk/pkg/chain/bitcoin"
	"github.com/didenkolab/mpc-sdk/pkg/chain/evm"
)

// ThresholdManager dispatches operations to the protocol implementations.
type ThresholdManager struct {
	frostOp  *FROSTBusinessOperation
	dkls23Op *DKLS23BusinessOperation
}

// NewThresholdManager creates a manager for all supported algorithms.
func NewThresholdManager() *ThresholdManager {
	return &ThresholdManager{
		frostOp:  NewFROSTBusinessOperation(),
		dkls23Op: NewDKLS23BusinessOperation(),
	}
}

// GetOperation returns the implementation of algorithm.
func (tm *ThresholdManager) GetOperation(algorithm SignatureAlgorithm) (BusinessOperation, error) {
	switch algorithm {
	case Ed25519FROST:
		return tm.frostOp, nil
	case ECDSASecp256k1:
		return tm.dkls23Op, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// CreateThresholdKeys generates all keyshares of a participants-of-threshold
// key in this process (in-memory demo mode).
func (tm *ThresholdManager) CreateThresholdKeys(algorithm SignatureAlgorithm, participants, threshold int, partyID uint8) ([]*KeyShare, error) {
	op, err := tm.GetOperation(algorithm)
	if err != nil {
		return nil, err
	}
	return op.GenerateThresholdKeys(&ThresholdConfig{
		Algorithm:    algorithm,
		Participants: participants,
		Threshold:    threshold,
		PartyID:      partyID,
		Mode:         ExecutionModeInMemoryDemo,
	})
}

// generateThresholdKeys implements GenerateThresholdKeys for both protocols.
func generateThresholdKeys(alg SignatureAlgorithm, config *ThresholdConfig) ([]*KeyShare, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}
	if config.Algorithm != alg {
		return nil, fmt.Errorf("unsupported algorithm: %s", config.Algorithm)
	}
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	partyIDs := make([]uint8, config.Participants)
	for i := range partyIDs {
		partyIDs[i] = uint8(i)
	}

	if config.Mode == ExecutionModeInMemoryDemo {
		coordinator, err := NewMultiPartyCoordinator(partyIDs, config.Threshold, alg)
		if err != nil {
			return nil, fmt.Errorf("failed to create multi-party coordinator: %w", err)
		}
		defer coordinator.Free()

		return coordinator.ExecuteDistributedDKG()
	}

	session, err := NewDKGSession(config.PartyID, partyIDs, config.Threshold, alg)
	if err != nil {
		return nil, fmt.Errorf("failed to create DKG session: %w", err)
	}
	defer session.Free()
	session.SetSessionID(config.SessionID)
	session.SetTransport(config.Transport)

	keyshare, err := session.ExecuteDKG()
	if err != nil {
		return nil, fmt.Errorf("distributed DKG failed: %w", err)
	}
	return []*KeyShare{keyshare}, nil
}

// WalletManager implements BusinessWallet for one algorithm.
type WalletManager struct {
	*ThresholdManager
	algorithm SignatureAlgorithm
	mode      ExecutionMode
	transport MessageTransport
	balancer  BalanceProvider
}

// NewWalletManager creates a wallet manager in prod mode.
func NewWalletManager(algorithm SignatureAlgorithm) *WalletManager {
	return NewWalletManagerWithMode(algorithm, ExecutionModeProd)
}

// NewWalletManagerWithMode creates a wallet manager in the given mode.
func NewWalletManagerWithMode(algorithm SignatureAlgorithm, mode ExecutionMode) *WalletManager {
	return &WalletManager{
		ThresholdManager: NewThresholdManager(),
		algorithm:        algorithm,
		mode:             mode,
	}
}

// SetTransport sets the default transport for key generation in prod mode.
func (wm *WalletManager) SetTransport(transport MessageTransport) {
	wm.transport = transport
}

// SetBalanceProvider sets the source used by GetBalance.
func (wm *WalletManager) SetBalanceProvider(provider BalanceProvider) {
	wm.balancer = provider
}

// GetAlgorithm returns the wallet's algorithm.
func (wm *WalletManager) GetAlgorithm() SignatureAlgorithm {
	return wm.algorithm
}

// GenerateThresholdKeys generates keys with config. Mode and Transport default
// to the manager's settings when unset in config.
func (wm *WalletManager) GenerateThresholdKeys(config *ThresholdConfig) ([]*KeyShare, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}
	if config.Algorithm != wm.algorithm {
		return nil, fmt.Errorf("algorithm mismatch: wallet uses %s, config uses %s",
			wm.algorithm, config.Algorithm)
	}

	cfg := *config
	if cfg.Mode == ExecutionModeProd {
		cfg.Mode = wm.mode
	}
	if cfg.Transport == nil {
		cfg.Transport = wm.transport
	}
	if cfg.Mode == ExecutionModeProd && cfg.SessionID == "" {
		// Parties on different machines must agree on the session ID.
		return nil, errors.New("session_id is required in prod mode")
	}

	op, err := wm.GetOperation(wm.algorithm)
	if err != nil {
		return nil, err
	}
	return op.GenerateThresholdKeys(&cfg)
}

// checkLocalSigning rejects in-process signing in prod mode, where a single
// process must never hold a signing quorum.
func (wm *WalletManager) checkLocalSigning(keyShares []*KeyShare) error {
	if wm.mode != ExecutionModeProd {
		return nil
	}
	if len(keyShares) != 1 {
		return errors.New("prod mode requires a single local keyshare; signing needs remote parties")
	}
	if keyShares[0] != nil && keyShares[0].Threshold > 1 {
		return fmt.Errorf("prod mode requires distributed signing; threshold=%d needs remote signers", keyShares[0].Threshold)
	}
	return nil
}

// SignMessage signs SHA-256(message) with the shares at signerIndices.
func (wm *WalletManager) SignMessage(message []byte, keyShares []*KeyShare, signerIndices []int) (*Signature, error) {
	if err := wm.checkLocalSigning(keyShares); err != nil {
		return nil, err
	}
	op, err := wm.GetOperation(wm.algorithm)
	if err != nil {
		return nil, err
	}
	return op.SignMessage(message, keyShares, signerIndices)
}

// VerifySignature verifies a signature produced by SignMessage.
func (wm *WalletManager) VerifySignature(message []byte, signature *Signature) (bool, error) {
	if signature == nil {
		return false, errors.New("signature is nil")
	}
	op, err := wm.GetOperation(signature.Algorithm)
	if err != nil {
		return false, err
	}
	return op.VerifySignature(message, signature)
}

// VerifyTransactionSignature verifies a signature produced by
// SignTransaction over the 32-byte txHash.
func (wm *WalletManager) VerifyTransactionSignature(txHash []byte, signature *Signature) (bool, error) {
	if signature == nil {
		return false, errors.New("signature is nil")
	}
	digest, err := toDigest(txHash)
	if err != nil {
		return false, err
	}
	op, err := wm.digestOperation(signature.Algorithm)
	if err != nil {
		return false, err
	}
	return op.verifyDigest(digest, signature)
}

// DeriveChildKey derives the share of a child key.
func (wm *WalletManager) DeriveChildKey(keyShare *KeyShare, derivationPath string) (*KeyShare, error) {
	if keyShare == nil {
		return nil, errors.New("key share is nil")
	}
	op, err := wm.GetOperation(keyShare.Algorithm)
	if err != nil {
		return nil, err
	}
	return op.DeriveChildKey(keyShare, derivationPath)
}

// GenerateAddress derives an address for keyShare's public key.
//
// Supported address types: for ECDSA "bitcoin"/"btc"/"" (P2WPKH),
// "bitcoin-legacy"/"btc-legacy" (P2PKH), "ethereum"/"eth", "bsc" and
// "polygon" (EIP-55 checksummed); for Ed25519 "solana"/"" (base58) and "near"
// (hex implicit account).
func (wm *WalletManager) GenerateAddress(keyShare *KeyShare, addressType string) (*WalletAddress, error) {
	if keyShare == nil {
		return nil, errors.New("key share is nil")
	}
	if keyShare.Algorithm != wm.algorithm {
		return nil, fmt.Errorf("key algorithm mismatch: expected %s, got %s",
			wm.algorithm, keyShare.Algorithm)
	}

	pubKeyBytes, err := hex.DecodeString(keyShare.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	var address string
	switch wm.algorithm {
	case Ed25519FROST:
		if len(pubKeyBytes) != 32 {
			return nil, fmt.Errorf("ed25519 public key must be 32 bytes, got %d", len(pubKeyBytes))
		}
		switch addressType {
		case "solana", "":
			address = base58.Encode(pubKeyBytes)
		case "near":
			address = hex.EncodeToString(pubKeyBytes)
		default:
			return nil, fmt.Errorf("unsupported address type %q for Ed25519", addressType)
		}

	case ECDSASecp256k1:
		if len(pubKeyBytes) != 33 {
			return nil, fmt.Errorf("ECDSA public key must be 33 bytes compressed, got %d", len(pubKeyBytes))
		}
		switch addressType {
		case "bitcoin", "btc", "":
			addr, err := bitcoin.DeriveP2WPKHAddress(pubKeyBytes, &chaincfg.MainNetParams)
			if err != nil {
				return nil, fmt.Errorf("failed to derive Bitcoin address: %w", err)
			}
			address = addr.EncodeAddress()
		case "bitcoin-legacy", "btc-legacy":
			addr, err := bitcoin.DeriveP2PKHAddress(pubKeyBytes, &chaincfg.MainNetParams)
			if err != nil {
				return nil, fmt.Errorf("failed to derive Bitcoin legacy address: %w", err)
			}
			address = addr.EncodeAddress()
		case "ethereum", "eth", "bsc", "polygon":
			ethAddr, err := evm.DeriveAddress(pubKeyBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to derive %s address: %w", addressType, err)
			}
			address = ethAddr.Hex()
		default:
			return nil, fmt.Errorf("unsupported address type %q for ECDSA", addressType)
		}

	default:
		return nil, fmt.Errorf("unsupported algorithm for address generation: %s", wm.algorithm)
	}

	return &WalletAddress{
		Algorithm: wm.algorithm,
		Address:   address,
		PublicKey: keyShare.PublicKey,
		Path:      keyShare.Path,
	}, nil
}

// SignTransaction signs a 32-byte transaction digest (for example a BIP-143
// sighash or an EIP-155 signing hash) as-is, without hashing it again, so the
// signature is valid on chain. Verify it with VerifyTransactionSignature.
func (wm *WalletManager) SignTransaction(txHash []byte, keyShares []*KeyShare, signerIndices []int, fromAddress *WalletAddress) (*Signature, error) {
	if fromAddress == nil {
		return nil, errors.New("from address is nil")
	}
	if fromAddress.Algorithm != wm.algorithm {
		return nil, fmt.Errorf("address algorithm mismatch: expected %s, got %s",
			wm.algorithm, fromAddress.Algorithm)
	}
	if err := wm.checkLocalSigning(keyShares); err != nil {
		return nil, err
	}
	digest, err := toDigest(txHash)
	if err != nil {
		return nil, err
	}
	op, err := wm.digestOperation(wm.algorithm)
	if err != nil {
		return nil, err
	}
	return op.signDigest(digest, keyShares, signerIndices)
}

func (wm *WalletManager) digestOperation(alg SignatureAlgorithm) (digestOperation, error) {
	op, err := wm.GetOperation(alg)
	if err != nil {
		return nil, err
	}
	dop, ok := op.(digestOperation)
	if !ok {
		return nil, fmt.Errorf("algorithm %s cannot sign raw digests", alg)
	}
	return dop, nil
}

func toDigest(txHash []byte) ([32]byte, error) {
	var digest [32]byte
	if len(txHash) != len(digest) {
		return digest, fmt.Errorf("txHash must be 32 bytes, got %d bytes", len(txHash))
	}
	copy(digest[:], txHash)
	return digest, nil
}

// GetBalance returns the balance of address from the configured
// BalanceProvider. Without a provider, demo mode returns a fixed placeholder
// balance and prod mode returns an error.
func (wm *WalletManager) GetBalance(address *WalletAddress) (string, error) {
	if address == nil {
		return "", errors.New("address is nil")
	}
	if wm.balancer != nil {
		return wm.balancer.Balance(address)
	}
	if wm.mode == ExecutionModeInMemoryDemo {
		switch address.Algorithm {
		case Ed25519FROST:
			return "1000.123456789", nil
		case ECDSASecp256k1:
			return "0.05432100", nil
		default:
			return "", fmt.Errorf("unsupported algorithm for balance check: %s", address.Algorithm)
		}
	}
	return "", errors.New("balance provider not configured (prod mode)")
}

// CreateCompleteWallet generates keys and the default address (Bitcoin
// P2WPKH for ECDSA, Solana for Ed25519). In prod mode the manager's transport
// is used; use GenerateThresholdKeys with a ThresholdConfig to set the
// session ID shared by the parties.
func (wm *WalletManager) CreateCompleteWallet(participants, threshold int, partyID uint8) (*CompleteWallet, error) {
	config := &ThresholdConfig{
		Algorithm:    wm.algorithm,
		Participants: participants,
		Threshold:    threshold,
		PartyID:      partyID,
		Mode:         wm.mode,
		Transport:    wm.transport,
	}

	keyShares, err := wm.GenerateThresholdKeys(config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	local := keyShares[0]
	for _, ks := range keyShares {
		if ks.PartyID == partyID {
			local = ks
			break
		}
	}

	var defaultAddrType string
	switch wm.algorithm {
	case Ed25519FROST:
		defaultAddrType = "solana"
	case ECDSASecp256k1:
		defaultAddrType = "bitcoin"
	}
	mainAddress, err := wm.GenerateAddress(local, defaultAddrType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate main address: %w", err)
	}

	return &CompleteWallet{
		Algorithm:   wm.algorithm,
		KeyShares:   keyShares,
		MainAddress: mainAddress,
		Config:      config,
	}, nil
}

// CompleteWallet bundles keyshares, the main address and the configuration.
type CompleteWallet struct {
	Algorithm   SignatureAlgorithm `json:"algorithm"`
	KeyShares   []*KeyShare        `json:"key_shares"`
	MainAddress *WalletAddress     `json:"main_address"`
	Config      *ThresholdConfig   `json:"config"`
}

// SignWithWallet signs message with the wallet's shares at signerIndices.
func (cw *CompleteWallet) SignWithWallet(message []byte, signerIndices []int, manager *WalletManager) (*Signature, error) {
	return manager.SignMessage(message, cw.KeyShares, signerIndices)
}

// GetAvailableSigners returns the indices of the wallet's keyshares.
func (cw *CompleteWallet) GetAvailableSigners() []int {
	signers := make([]int, len(cw.KeyShares))
	for i := range cw.KeyShares {
		signers[i] = i
	}
	return signers
}

// CanSign reports whether signerIndices are distinct, valid keyshare indices
// that reach the threshold.
func (cw *CompleteWallet) CanSign(signerIndices []int) bool {
	seen := make(map[int]bool, len(signerIndices))
	for _, idx := range signerIndices {
		if idx < 0 || idx >= len(cw.KeyShares) || seen[idx] {
			return false
		}
		seen[idx] = true
	}
	return cw.Config != nil && len(seen) >= cw.Config.Threshold
}

// lowerHex normalizes a hex string to lowercase.
func lowerHex(s string) string { return strings.ToLower(s) }

// equalHex compares two hex strings case-insensitively in constant time.
func equalHex(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(lowerHex(a)), []byte(lowerHex(b))) == 1
}
