// Package mpcdemo runs complete threshold protocols for the examples.
//
// Every party lives in the same process and messages are routed in memory, so
// an example can show DKG and signing end to end without a coordinator or
// network transport. In a real deployment each party runs on its own device
// and exchanges exactly the same messages over an authenticated channel.
package mpcdemo

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/didenkolab/mpc-sdk/pkg/dkls23"
)

// DKLS23Keygen runs a DKLs23 distributed key generation for n parties with the
// given signing threshold and returns one keyshare (JSON) per party, indexed by
// party ID. If ranks is non-nil, it must have n entries and the key is created
// in hierarchical mode (signing uses Birkhoff instead of Lagrange coefficients).
func DKLS23Keygen(n, threshold int, ranks []uint8) ([]string, error) {
	if ranks != nil && len(ranks) != n {
		return nil, fmt.Errorf("got %d ranks for %d parties", len(ranks), n)
	}

	parties := make([]*dkls23.DKGState, n)
	defer func() {
		for _, p := range parties {
			if p != nil {
				p.Free()
			}
		}
	}()
	for i := range parties {
		var err error
		if ranks != nil {
			parties[i], err = dkls23.NewDKGStateWithRanks(uint8(i), ranks, threshold)
		} else {
			parties[i], err = dkls23.NewDKGState(uint8(i), n, threshold)
		}
		if err != nil {
			return nil, fmt.Errorf("init party %d: %w", i, err)
		}
	}

	// Round 1: every party broadcasts a commitment.
	msg1 := make([]json.RawMessage, n)
	for i, p := range parties {
		out, err := p.GenerateMsg1()
		if err != nil {
			return nil, fmt.Errorf("party %d: round 1: %w", i, err)
		}
		msg1[i] = json.RawMessage(out)
	}

	// Round 2: process broadcasts, emit point-to-point messages.
	var msg2 []json.RawMessage
	for i, p := range parties {
		out, err := p.HandleMsg1(fromOthers(msg1, i))
		if err != nil {
			return nil, fmt.Errorf("party %d: round 2: %w", i, err)
		}
		if msg2, err = appendList(msg2, out); err != nil {
			return nil, fmt.Errorf("party %d: round 2: %w", i, err)
		}
	}

	// Round 3: process point-to-point messages, emit the next batch.
	var msg3 []json.RawMessage
	for i, p := range parties {
		in, err := addressedTo(msg2, uint8(i))
		if err != nil {
			return nil, err
		}
		out, err := p.HandleMsg2(in)
		if err != nil {
			return nil, fmt.Errorf("party %d: round 3: %w", i, err)
		}
		if msg3, err = appendList(msg3, out); err != nil {
			return nil, fmt.Errorf("party %d: round 3: %w", i, err)
		}
	}

	// Round 4: reveal commitments, then verify everything received so far.
	commitments := make([]string, n)
	for i, p := range parties {
		c, err := p.CalculateCommitment2()
		if err != nil {
			return nil, fmt.Errorf("party %d: commitment: %w", i, err)
		}
		commitments[i] = c
	}
	msg4 := make([]json.RawMessage, n)
	for i, p := range parties {
		in, err := addressedTo(msg3, uint8(i))
		if err != nil {
			return nil, err
		}
		out, err := p.HandleMsg3(in, commitments)
		if err != nil {
			return nil, fmt.Errorf("party %d: round 4: %w", i, err)
		}
		msg4[i] = json.RawMessage(out)
	}

	// Finalize: every party derives its keyshare.
	keyshares := make([]string, n)
	for i, p := range parties {
		ks, err := p.HandleMsg4(fromOthers(msg4, i))
		if err != nil {
			return nil, fmt.Errorf("party %d: finalize: %w", i, err)
		}
		keyshares[i] = ks
	}
	return keyshares, nil
}

// DKLS23Sign runs a DKLs23 signing session between exactly threshold holders
// of keyshares from the same key and returns the 64-byte r||s signature over
// hash (with low S).
func DKLS23Sign(keyshares []string, hash [32]byte) ([]byte, error) {
	if len(keyshares) < 2 {
		return nil, errors.New("signing needs at least two keyshares")
	}

	type signer struct {
		id    uint8
		state *dkls23.DSGState
	}
	signers := make([]signer, len(keyshares))
	defer func() {
		for _, s := range signers {
			if s.state != nil {
				s.state.Free()
			}
		}
	}()
	for i, ks := range keyshares {
		var meta struct {
			PartyID uint8 `json:"party_id"`
		}
		if err := json.Unmarshal([]byte(ks), &meta); err != nil {
			return nil, fmt.Errorf("keyshare %d: %w", i, err)
		}
		st, err := dkls23.NewDSGState(ks, "m")
		if err != nil {
			return nil, fmt.Errorf("init signer %d: %w", meta.PartyID, err)
		}
		signers[i] = signer{id: meta.PartyID, state: st}
	}

	msg1 := make([]json.RawMessage, len(signers))
	for i, s := range signers {
		out, err := s.state.GenerateMsg1()
		if err != nil {
			return nil, fmt.Errorf("signer %d: round 1: %w", s.id, err)
		}
		msg1[i] = json.RawMessage(out)
	}

	var msg2 []json.RawMessage
	for i, s := range signers {
		out, err := s.state.HandleMsg1(fromOthers(msg1, i))
		if err != nil {
			return nil, fmt.Errorf("signer %d: round 2: %w", s.id, err)
		}
		if msg2, err = appendList(msg2, out); err != nil {
			return nil, err
		}
	}

	var msg3 []json.RawMessage
	for _, s := range signers {
		in, err := addressedTo(msg2, s.id)
		if err != nil {
			return nil, err
		}
		out, err := s.state.HandleMsg2(in)
		if err != nil {
			return nil, fmt.Errorf("signer %d: round 3: %w", s.id, err)
		}
		if msg3, err = appendList(msg3, out); err != nil {
			return nil, err
		}
	}

	// Each signer turns the last round into a presignature, then into a
	// partial signature on the message hash. The partial of one signer is
	// combined with the broadcast "msg4" of every other signer.
	var first json.RawMessage
	var others []interface{}
	for i, s := range signers {
		in, err := addressedTo(msg3, s.id)
		if err != nil {
			return nil, err
		}
		presig, err := s.state.HandleMsg3(in)
		if err != nil {
			return nil, fmt.Errorf("signer %d: presignature: %w", s.id, err)
		}
		out, err := dkls23.CreatePartialSignature(presig, hash)
		if err != nil {
			return nil, fmt.Errorf("signer %d: partial signature: %w", s.id, err)
		}
		var partial struct {
			Partial json.RawMessage `json:"partial"`
			Msg4    json.RawMessage `json:"msg4"`
		}
		if err := json.Unmarshal([]byte(out), &partial); err != nil {
			return nil, fmt.Errorf("signer %d: partial signature: %w", s.id, err)
		}
		if i == 0 {
			first = partial.Partial
		} else {
			others = append(others, partial.Msg4)
		}
	}

	sigHex, err := dkls23.CombineSignatures(string(first), others)
	if err != nil {
		return nil, fmt.Errorf("combine: %w", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	if len(sig) != 64 {
		return nil, fmt.Errorf("signature is %d bytes, want 64", len(sig))
	}
	return sig, nil
}

// DKLS23PublicKey returns the 33-byte compressed secp256k1 group public key
// recorded in a keyshare.
func DKLS23PublicKey(keyshare string) ([]byte, error) {
	pub, err := dkls23.DeriveChildPublicKey(keyshare, "m")
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(pub)
}

// VerifyECDSA checks a 64-byte r||s secp256k1 signature over hash.
func VerifyECDSA(pubKey []byte, hash [32]byte, sig []byte) error {
	pk, err := btcec.ParsePubKey(pubKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	parsed, err := ParseRS(sig)
	if err != nil {
		return err
	}
	if !parsed.Verify(hash[:], pk) {
		return errors.New("ECDSA signature does not verify")
	}
	return nil
}

// ParseRS converts a 64-byte r||s signature into a btcec ECDSA signature.
func ParseRS(sig []byte) (*ecdsa.Signature, error) {
	if len(sig) != 64 {
		return nil, fmt.Errorf("signature is %d bytes, want 64", len(sig))
	}
	var r, s btcec.ModNScalar
	if overflow := r.SetByteSlice(sig[:32]); overflow || r.IsZero() {
		return nil, errors.New("invalid r in signature")
	}
	if overflow := s.SetByteSlice(sig[32:]); overflow || s.IsZero() {
		return nil, errors.New("invalid s in signature")
	}
	return ecdsa.NewSignature(&r, &s), nil
}

// fromOthers returns every broadcast message except the one sent by self.
func fromOthers(msgs []json.RawMessage, self int) []interface{} {
	out := make([]interface{}, 0, len(msgs)-1)
	for i, m := range msgs {
		if i != self {
			out = append(out, m)
		}
	}
	return out
}

// appendList decodes a JSON array of messages and appends its items to pool.
func appendList(pool []json.RawMessage, list string) ([]json.RawMessage, error) {
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(list), &items); err != nil {
		return nil, fmt.Errorf("expected a JSON array of messages: %w", err)
	}
	return append(pool, items...), nil
}

// addressedTo selects the point-to-point messages whose to_id is id.
func addressedTo(pool []json.RawMessage, id uint8) ([]interface{}, error) {
	var out []interface{}
	for _, m := range pool {
		var hdr struct {
			ToID *uint16 `json:"to_id"`
		}
		if err := json.Unmarshal(m, &hdr); err != nil {
			return nil, fmt.Errorf("parse message header: %w", err)
		}
		if hdr.ToID == nil {
			return nil, errors.New("point-to-point message without to_id")
		}
		if *hdr.ToID == uint16(id) {
			out = append(out, m)
		}
	}
	return out, nil
}
