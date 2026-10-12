package threshold

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/didenkolab/mpc-sdk/pkg/frost"
)

// ErrDerivationUnsupported is returned when the protocol cannot derive the
// requested child key.
var ErrDerivationUnsupported = errors.New("child key derivation is not supported")

// FROSTBusinessOperation implements BusinessOperation with FROST threshold
// Ed25519.
type FROSTBusinessOperation struct {
	algorithm SignatureAlgorithm
}

// NewFROSTBusinessOperation returns the FROST implementation.
func NewFROSTBusinessOperation() *FROSTBusinessOperation {
	return &FROSTBusinessOperation{algorithm: Ed25519FROST}
}

// GetAlgorithm returns Ed25519FROST.
func (f *FROSTBusinessOperation) GetAlgorithm() SignatureAlgorithm {
	return f.algorithm
}

// GenerateThresholdKeys runs FROST key generation. In prod mode only the
// local party runs and a single keyshare is returned; in demo mode all
// parties run concurrently in this process and every keyshare is returned.
func (f *FROSTBusinessOperation) GenerateThresholdKeys(config *ThresholdConfig) ([]*KeyShare, error) {
	return generateThresholdKeys(Ed25519FROST, config)
}

// SignMessage signs SHA-256(message) by running all selected signers in this
// process.
func (f *FROSTBusinessOperation) SignMessage(message []byte, keyShares []*KeyShare, signerIndices []int) (*Signature, error) {
	return f.signDigest(sha256.Sum256(message), keyShares, signerIndices)
}

func (f *FROSTBusinessOperation) signDigest(digest [32]byte, keyShares []*KeyShare, signerIndices []int) (*Signature, error) {
	signers, err := selectSigners(Ed25519FROST, keyShares, signerIndices)
	if err != nil {
		return nil, err
	}

	states := make([]*frost.SigningState, 0, len(signers))
	defer func() {
		for _, st := range states {
			st.Free()
		}
	}()
	for _, ks := range signers {
		st, err := frost.NewSigningState(ks.KeyData, digest)
		if err != nil {
			return nil, fmt.Errorf("failed to create signing state for party %d: %w", ks.PartyID, err)
		}
		states = append(states, st)
	}

	// Round 1: nonce commitments.
	commitments := make([]string, len(states))
	for i, st := range states {
		if commitments[i], err = st.GenerateMsg1(); err != nil {
			return nil, fmt.Errorf("signer %d: generate commitments: %w", signers[i].PartyID, err)
		}
	}

	// Round 2: every signer produces its signature share.
	shares := make([]string, len(states))
	for i, st := range states {
		if shares[i], err = st.HandleMsg1(othersExcept(i, commitments)); err != nil {
			return nil, fmt.Errorf("signer %d: signature share: %w", signers[i].PartyID, err)
		}
	}

	sigHex, err := frost.CombineSignatures(shares[0], othersExcept(0, shares))
	if err != nil {
		return nil, fmt.Errorf("failed to combine signatures: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode final FROST signature: %w", err)
	}

	return &Signature{
		Algorithm: Ed25519FROST,
		Data:      sig,
		PublicKey: signers[0].PublicKey,
	}, nil
}

// VerifySignature verifies an Ed25519 signature over SHA-256(message).
func (f *FROSTBusinessOperation) VerifySignature(message []byte, signature *Signature) (bool, error) {
	return f.verifyDigest(sha256.Sum256(message), signature)
}

func (f *FROSTBusinessOperation) verifyDigest(digest [32]byte, signature *Signature) (bool, error) {
	if signature == nil {
		return false, errors.New("signature is nil")
	}
	if signature.Algorithm != Ed25519FROST {
		return false, fmt.Errorf("unsupported signature algorithm: %s", signature.Algorithm)
	}
	valid, err := frost.VerifySignature(signature.PublicKey, digest[:], hex.EncodeToString(signature.Data))
	if err != nil {
		return false, fmt.Errorf("failed to verify FROST signature: %w", err)
	}
	return valid, nil
}

// DeriveChildKey returns the share for the child key at derivationPath. The
// FROST library does not implement hierarchical derivation yet, so any path
// other than the root "m" returns ErrDerivationUnsupported rather than
// silently reusing the parent key.
func (f *FROSTBusinessOperation) DeriveChildKey(keyShare *KeyShare, derivationPath string) (*KeyShare, error) {
	if keyShare == nil {
		return nil, errors.New("key share is nil")
	}
	if keyShare.Algorithm != Ed25519FROST {
		return nil, fmt.Errorf("unsupported key algorithm: %s", keyShare.Algorithm)
	}
	if derivationPath == "" || derivationPath[0] != 'm' {
		return nil, fmt.Errorf("derivation path must start with 'm' (SLIP-0010 format), got: %q", derivationPath)
	}

	res, err := frost.DerivePublicKey(keyShare.KeyData, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("failed to derive Ed25519 public key: %w", err)
	}
	publicKey, err := parseDerivedPublicKey(res)
	if err != nil {
		return nil, err
	}

	parentPath := pathOrRoot(keyShare.Path)
	if derivationPath != parentPath && equalHex(publicKey, keyShare.PublicKey) {
		return nil, fmt.Errorf("FROST path %q: %w", derivationPath, ErrDerivationUnsupported)
	}

	keyData, err := frost.DeriveKeyshare(keyShare.KeyData, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("failed to derive FROST keyshare: %w", err)
	}

	child := *keyShare
	child.KeyData = keyData
	child.PublicKey = publicKey
	child.Path = derivationPath
	return &child, nil
}
