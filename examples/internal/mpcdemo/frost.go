package mpcdemo

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/didenkolab/mpc-sdk/pkg/frost"
)

// FROSTKeygen runs a FROST (Ed25519) distributed key generation for n parties
// with the given signing threshold and returns one keyshare (JSON) per party.
// FROST participant identifiers are 1..n; keyshare i belongs to participant i+1.
func FROSTKeygen(n, threshold int) ([]string, error) {
	parties := make([]*frost.DKGState, n)
	defer func() {
		for _, p := range parties {
			if p != nil {
				p.Free()
			}
		}
	}()
	for i := range parties {
		var err error
		if parties[i], err = frost.NewDKGState(uint8(i+1), n, threshold); err != nil {
			return nil, fmt.Errorf("init participant %d: %w", i+1, err)
		}
	}

	// Round 1: every participant broadcasts its commitment.
	msg1 := make([]json.RawMessage, n)
	for i, p := range parties {
		out, err := p.GenerateMsg1()
		if err != nil {
			return nil, fmt.Errorf("participant %d: round 1: %w", i+1, err)
		}
		msg1[i] = json.RawMessage(out)
	}

	// Round 2: every participant sends one secret share to each peer.
	msg2 := make([]string, n)
	for i, p := range parties {
		out, err := p.HandleMsg1(fromOthers(msg1, i))
		if err != nil {
			return nil, fmt.Errorf("participant %d: round 2: %w", i+1, err)
		}
		msg2[i] = out
	}

	// Round 3: verify the shares addressed to each participant and derive
	// its keyshare.
	keyshares := make([]string, n)
	for i, p := range parties {
		in, err := frost.Round2MessagesFor(uint8(i+1), msg2...)
		if err != nil {
			return nil, err
		}
		ks, err := p.HandleMsg2(in)
		if err != nil {
			return nil, fmt.Errorf("participant %d: round 3: %w", i+1, err)
		}
		keyshares[i] = ks
	}
	return keyshares, nil
}

// FROSTSign runs a FROST signing session between the holders of the given
// keyshares (at least threshold of them) and returns the 64-byte Ed25519
// signature over message. As with plain Ed25519, the message is signed as-is
// (hashing is part of the signature scheme).
func FROSTSign(keyshares []string, message []byte) ([]byte, error) {
	if len(keyshares) < 2 {
		return nil, errors.New("signing needs at least two keyshares")
	}
	signers := make([]*frost.SigningState, len(keyshares))
	defer func() {
		for _, s := range signers {
			if s != nil {
				s.Free()
			}
		}
	}()
	for i, ks := range keyshares {
		var err error
		if signers[i], err = frost.NewSigningStateForMessage(ks, message); err != nil {
			return nil, fmt.Errorf("init signer %d: %w", i, err)
		}
	}

	// Round 1: every signer broadcasts its nonce commitments.
	commitments := make([]json.RawMessage, len(signers))
	for i, s := range signers {
		out, err := s.GenerateMsg1()
		if err != nil {
			return nil, fmt.Errorf("signer %d: round 1: %w", i, err)
		}
		commitments[i] = json.RawMessage(out)
	}

	// Round 2: every signer produces its signature share.
	shares := make([]string, len(signers))
	for i, s := range signers {
		var err error
		if shares[i], err = s.HandleMsg1(fromOthers(commitments, i)); err != nil {
			return nil, fmt.Errorf("signer %d: round 2: %w", i, err)
		}
	}

	// Aggregate: any party can combine the shares into one signature.
	others := make([]interface{}, 0, len(shares)-1)
	for _, s := range shares[1:] {
		others = append(others, json.RawMessage(s))
	}
	sigHex, err := frost.CombineSignatures(shares[0], others)
	if err != nil {
		return nil, fmt.Errorf("aggregate: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

// FROSTPublicKey returns the 32-byte Ed25519 group public key of a keyshare.
func FROSTPublicKey(keyshare string) ([]byte, error) {
	out, err := frost.DerivePublicKey(keyshare, "m")
	if err != nil {
		return nil, err
	}
	pub, err := derivedKey(out)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	return pub, nil
}

// derivedKey extracts derived_public_key from a DerivePublicKey response.
func derivedKey(resp string) ([]byte, error) {
	var parsed struct {
		DerivedPublicKey string `json:"derived_public_key"`
	}
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	if parsed.DerivedPublicKey == "" {
		return nil, errors.New("empty derived_public_key")
	}
	return hex.DecodeString(parsed.DerivedPublicKey)
}

// VerifyEd25519 checks an Ed25519 signature with the standard library.
func VerifyEd25519(pubKey, message, sig []byte) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public key is %d bytes, want %d", len(pubKey), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(pubKey, message, sig) {
		return errors.New("Ed25519 signature does not verify")
	}
	return nil
}
