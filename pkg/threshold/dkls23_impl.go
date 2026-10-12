package threshold

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/didenkolab/mpc-sdk/pkg/dkls23"
)

// DKLS23BusinessOperation implements BusinessOperation with DKLs23 threshold
// ECDSA over secp256k1.
type DKLS23BusinessOperation struct {
	algorithm SignatureAlgorithm
}

// NewDKLS23BusinessOperation returns the DKLs23 implementation.
func NewDKLS23BusinessOperation() *DKLS23BusinessOperation {
	return &DKLS23BusinessOperation{algorithm: ECDSASecp256k1}
}

// GetAlgorithm returns ECDSASecp256k1.
func (d *DKLS23BusinessOperation) GetAlgorithm() SignatureAlgorithm {
	return d.algorithm
}

// GenerateThresholdKeys runs DKLs23 key generation. In prod mode only the
// local party runs and a single keyshare is returned; in demo mode all
// parties run concurrently in this process and every keyshare is returned.
func (d *DKLS23BusinessOperation) GenerateThresholdKeys(config *ThresholdConfig) ([]*KeyShare, error) {
	return generateThresholdKeys(ECDSASecp256k1, config)
}

// SignMessage signs SHA-256(message) by running the selected signers in this
// process. keyShares are the shares of one key; signerIndices select at
// least Threshold of them. DKLs23 signs with exactly Threshold parties, so
// only the first Threshold entries of signerIndices take part.
func (d *DKLS23BusinessOperation) SignMessage(message []byte, keyShares []*KeyShare, signerIndices []int) (*Signature, error) {
	return d.signDigest(sha256.Sum256(message), keyShares, signerIndices)
}

func (d *DKLS23BusinessOperation) signDigest(digest [32]byte, keyShares []*KeyShare, signerIndices []int) (*Signature, error) {
	signers, err := selectSigners(ECDSASecp256k1, keyShares, signerIndices)
	if err != nil {
		return nil, err
	}
	// The protocol requires exactly threshold signers: each one adds 1/t of
	// the BIP32 derivation offset to its share.
	signers = signers[:signers[0].Threshold]

	ids := make([]uint8, len(signers))
	states := make([]*dkls23.DSGState, 0, len(signers))
	defer func() {
		for _, st := range states {
			st.Free()
		}
	}()
	for i, ks := range signers {
		ids[i] = ks.PartyID
		st, err := dkls23.NewDSGState(ks.KeyData, pathOrRoot(ks.Path))
		if err != nil {
			return nil, fmt.Errorf("failed to create DSG state for party %d: %w", ks.PartyID, err)
		}
		states = append(states, st)
	}

	// Round 1: broadcast.
	msg1 := make([]string, len(states))
	for i, st := range states {
		if msg1[i], err = st.GenerateMsg1(); err != nil {
			return nil, fmt.Errorf("signer %d: generate msg1: %w", ids[i], err)
		}
	}

	// Round 2: handle the others' msg1, route msg2 point-to-point.
	msg2 := make([]string, len(states))
	for i, st := range states {
		if msg2[i], err = st.HandleMsg1(othersExcept(i, msg1)); err != nil {
			return nil, fmt.Errorf("signer %d: handle msg1: %w", ids[i], err)
		}
	}
	inbox2, err := routeByToID(ids, msg2)
	if err != nil {
		return nil, fmt.Errorf("route msg2: %w", err)
	}

	// Round 3: handle msg2, route msg3 point-to-point.
	msg3 := make([]string, len(states))
	for i, st := range states {
		if msg3[i], err = st.HandleMsg2(inbox2[i]); err != nil {
			return nil, fmt.Errorf("signer %d: handle msg2: %w", ids[i], err)
		}
	}
	inbox3, err := routeByToID(ids, msg3)
	if err != nil {
		return nil, fmt.Errorf("route msg3: %w", err)
	}

	// Presignatures and partial signatures.
	type partialResult struct {
		Partial json.RawMessage `json:"partial"`
		Msg4    json.RawMessage `json:"msg4"`
	}
	partials := make([]partialResult, len(states))
	for i, st := range states {
		presig, err := st.HandleMsg3(inbox3[i])
		if err != nil {
			return nil, fmt.Errorf("signer %d: handle msg3: %w", ids[i], err)
		}
		res, err := dkls23.CreatePartialSignature(presig, digest)
		if err != nil {
			return nil, fmt.Errorf("signer %d: create partial signature: %w", ids[i], err)
		}
		if err := json.Unmarshal([]byte(res), &partials[i]); err != nil {
			return nil, fmt.Errorf("signer %d: parse partial signature: %w", ids[i], err)
		}
	}

	// The first signer combines its partial signature with the others' msg4.
	others := make([]interface{}, 0, len(partials)-1)
	for _, p := range partials[1:] {
		others = append(others, p.Msg4)
	}
	sigHex, err := dkls23.CombineSignatures(string(partials[0].Partial), others)
	if err != nil {
		return nil, fmt.Errorf("failed to combine signatures: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != 64 {
		return nil, fmt.Errorf("unexpected signature encoding %q", sigHex)
	}

	return &Signature{
		Algorithm: ECDSASecp256k1,
		Data:      sig,
		R:         hex.EncodeToString(sig[:32]),
		S:         hex.EncodeToString(sig[32:]),
		PublicKey: signers[0].PublicKey,
	}, nil
}

// VerifySignature verifies an ECDSA signature over SHA-256(message).
func (d *DKLS23BusinessOperation) VerifySignature(message []byte, signature *Signature) (bool, error) {
	return d.verifyDigest(sha256.Sum256(message), signature)
}

func (d *DKLS23BusinessOperation) verifyDigest(digest [32]byte, signature *Signature) (bool, error) {
	if signature == nil {
		return false, errors.New("signature is nil")
	}
	if signature.Algorithm != ECDSASecp256k1 {
		return false, fmt.Errorf("unsupported signature algorithm: %s", signature.Algorithm)
	}

	pubKeyBytes, err := hex.DecodeString(signature.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(pubKeyBytes) != 33 {
		return false, fmt.Errorf("public key must be 33 bytes compressed, got %d", len(pubKeyBytes))
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	var rBytes, sBytes []byte
	switch {
	case signature.R != "" && signature.S != "":
		if rBytes, err = hex.DecodeString(signature.R); err != nil {
			return false, fmt.Errorf("failed to decode R: %w", err)
		}
		if sBytes, err = hex.DecodeString(signature.S); err != nil {
			return false, fmt.Errorf("failed to decode S: %w", err)
		}
	case len(signature.Data) == 64:
		rBytes, sBytes = signature.Data[:32], signature.Data[32:]
	default:
		return false, errors.New("signature missing R/S components")
	}
	if len(rBytes) != 32 || len(sBytes) != 32 {
		return false, errors.New("r and s must be 32 bytes each")
	}

	var r, s btcec.ModNScalar
	if r.SetByteSlice(rBytes) || s.SetByteSlice(sBytes) {
		return false, nil
	}
	return ecdsa.NewSignature(&r, &s).Verify(digest[:], pubKey), nil
}

// DeriveChildKey returns the share for the BIP32 child key at
// derivationPath, an absolute path from the root key such as
// "m/44'/60'/0'/0/0". The returned share keeps the root KeyData and signs
// for the child public key by deriving at signing time.
func (d *DKLS23BusinessOperation) DeriveChildKey(keyShare *KeyShare, derivationPath string) (*KeyShare, error) {
	if keyShare == nil {
		return nil, errors.New("key share is nil")
	}
	if keyShare.Algorithm != ECDSASecp256k1 {
		return nil, fmt.Errorf("unsupported key algorithm: %s", keyShare.Algorithm)
	}
	if derivationPath == "" || derivationPath[0] != 'm' {
		return nil, fmt.Errorf("derivation path must start with 'm' (BIP32 format), got: %q", derivationPath)
	}

	publicKey, err := dkls23.DeriveChildPublicKey(keyShare.KeyData, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	child := *keyShare
	child.PublicKey = lowerHex(publicKey)
	child.Path = derivationPath
	return &child, nil
}

// ========================================================================
// Shared helpers for in-process signing
// ========================================================================

// pathOrRoot returns path, or "m" when it is empty.
func pathOrRoot(path string) string {
	if path == "" {
		return "m"
	}
	return path
}

// selectSigners validates signerIndices against keyShares and returns the
// selected shares.
func selectSigners(alg SignatureAlgorithm, keyShares []*KeyShare, signerIndices []int) ([]*KeyShare, error) {
	if len(keyShares) == 0 {
		return nil, errors.New("no key shares provided")
	}
	for i, ks := range keyShares {
		if ks == nil {
			return nil, fmt.Errorf("key share %d is nil", i)
		}
		if ks.Algorithm != alg {
			return nil, fmt.Errorf("keyshare %d uses wrong algorithm: %s", i, ks.Algorithm)
		}
	}
	threshold := keyShares[0].Threshold
	if threshold < 1 {
		return nil, fmt.Errorf("invalid threshold %d in key share", threshold)
	}
	if len(signerIndices) < threshold {
		return nil, fmt.Errorf("insufficient signers: need %d, got %d", threshold, len(signerIndices))
	}

	seen := make(map[int]bool, len(signerIndices))
	parties := make(map[uint8]bool, len(signerIndices))
	signers := make([]*KeyShare, 0, len(signerIndices))
	for _, idx := range signerIndices {
		if idx < 0 || idx >= len(keyShares) {
			return nil, fmt.Errorf("signer index %d out of range", idx)
		}
		if seen[idx] {
			return nil, fmt.Errorf("duplicate signer index %d", idx)
		}
		seen[idx] = true

		ks := keyShares[idx]
		if parties[ks.PartyID] {
			return nil, fmt.Errorf("duplicate party ID %d among signers", ks.PartyID)
		}
		parties[ks.PartyID] = true
		if len(signers) > 0 {
			first := signers[0]
			if !equalHex(ks.PublicKey, first.PublicKey) || pathOrRoot(ks.Path) != pathOrRoot(first.Path) {
				return nil, errors.New("signers hold shares of different keys or paths")
			}
		}
		signers = append(signers, ks)
	}
	return signers, nil
}

// othersExcept decodes every broadcast message except the one at index self.
func othersExcept(self int, msgs []string) []interface{} {
	out := make([]interface{}, 0, len(msgs)-1)
	for i, m := range msgs {
		if i != self {
			out = append(out, json.RawMessage(m))
		}
	}
	return out
}

// routeByToID splits the P2P output arrays of the signers (in the order of
// ids) into per-signer inboxes using each message's "to_id".
func routeByToID(ids []uint8, outputs []string) ([][]interface{}, error) {
	index := make(map[int]int, len(ids))
	for i, id := range ids {
		index[int(id)] = i
	}
	inboxes := make([][]interface{}, len(ids))
	for sender, out := range outputs {
		var items []json.RawMessage
		if err := json.Unmarshal([]byte(out), &items); err != nil {
			return nil, fmt.Errorf("parse output of party %d: %w", ids[sender], err)
		}
		for _, item := range items {
			var hdr p2pHeader
			if err := json.Unmarshal(item, &hdr); err != nil {
				return nil, fmt.Errorf("parse message header from party %d: %w", ids[sender], err)
			}
			if hdr.ToID == nil {
				return nil, fmt.Errorf("message from party %d has no to_id", ids[sender])
			}
			to, ok := index[*hdr.ToID]
			if !ok {
				return nil, fmt.Errorf("message from party %d addressed to non-signer %d", ids[sender], *hdr.ToID)
			}
			inboxes[to] = append(inboxes[to], item)
		}
	}
	return inboxes, nil
}
