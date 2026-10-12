// Package sdk is a thin, round-oriented facade over the DKLs23 and FROST
// bindings. Every protocol message is a json.RawMessage (RawMsg), so callers
// can move messages over any transport without decoding them.
//
// Party IDs are 0-based for DKLs23 and 1-based for FROST, matching the
// underlying protocol packages. Point-to-point outputs are JSON arrays: split
// them with DecodeList and route each element by its "to_id" field (see
// FilterByToID).
package sdk

import (
	"encoding/json"
	"errors"

	"github.com/didenkolab/mpc-sdk/pkg/dkls23"
	"github.com/didenkolab/mpc-sdk/pkg/frost"
)

// RawMsg is a protocol message. It must contain valid JSON.
type RawMsg = json.RawMessage

// ---------- Shared helpers ----------

// parseList converts messages into values accepted by the protocol bindings.
// Valid JSON is passed through unchanged; anything else is sent as a JSON
// string.
func parseList(msgs []RawMsg) []interface{} {
	out := make([]interface{}, len(msgs))
	for i, m := range msgs {
		if json.Valid(m) {
			out[i] = m
		} else {
			out[i] = string(m)
		}
	}
	return out
}

// toRaw wraps a protocol output, which must be valid JSON.
func toRaw(s string) (RawMsg, error) {
	raw := RawMsg(s)
	if !json.Valid(raw) {
		return nil, errors.New("sdk: message is not valid JSON")
	}
	return raw, nil
}

// wrap returns the output of a protocol call as a RawMsg.
func wrap(s string, err error) (RawMsg, error) {
	if err != nil {
		return nil, err
	}
	return toRaw(s)
}

// DecodeList splits a JSON array into its elements. A JSON object, or any
// other non-empty payload, is returned as a one-element list.
func DecodeList(msg RawMsg) ([]RawMsg, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(msg, &items); err == nil {
		return items, nil
	}
	if len(msg) == 0 {
		return nil, errors.New("sdk: decode list: empty message")
	}
	return []RawMsg{msg}, nil
}

// FilterByToID returns the messages whose "to_id" field equals target.
// Messages without a "to_id" are dropped. Use it to route point-to-point
// DKLs23 messages (DKG msg2/msg3, signing msg2/msg3).
func FilterByToID(target uint8, msgs []RawMsg) []RawMsg {
	var res []RawMsg
	for _, m := range msgs {
		var hdr struct {
			ToID *int `json:"to_id"`
		}
		if err := json.Unmarshal(m, &hdr); err != nil || hdr.ToID == nil {
			continue
		}
		if *hdr.ToID == int(target) {
			res = append(res, m)
		}
	}
	return res
}

// ---------- DKLs23: key generation ----------

// DKLS23DKG is one party's DKLs23 key generation. It must be released with
// Close.
type DKLS23DKG struct {
	state *dkls23.DKGState
}

// NewDKLS23DKG starts key generation for partyID (0-based) of a
// threshold-of-parties key.
func NewDKLS23DKG(partyID uint8, parties, threshold int) (*DKLS23DKG, error) {
	state, err := dkls23.NewDKGState(partyID, parties, threshold)
	if err != nil {
		return nil, err
	}
	return &DKLS23DKG{state: state}, nil
}

// Round1 returns the message to broadcast.
func (s *DKLS23DKG) Round1() (RawMsg, error) {
	return wrap(s.state.GenerateMsg1())
}

// Round2 takes the other parties' Round1 messages and returns an array of
// point-to-point messages.
func (s *DKLS23DKG) Round2(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg1(parseList(msgs)))
}

// Round3 takes the Round2 messages addressed to this party and returns an
// array of point-to-point messages.
func (s *DKLS23DKG) Round3(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg2(parseList(msgs)))
}

// Commitment2 returns this party's commitment, which every party needs for
// Round4.
func (s *DKLS23DKG) Commitment2() (string, error) {
	return s.state.CalculateCommitment2()
}

// Round4 takes the Round3 messages addressed to this party and the
// commitments of all parties ordered by party ID, and returns the message to
// broadcast.
func (s *DKLS23DKG) Round4(msgs []RawMsg, commitments []string) (RawMsg, error) {
	return wrap(s.state.HandleMsg3(parseList(msgs), commitments))
}

// Finalize takes the other parties' Round4 messages and returns the keyshare.
func (s *DKLS23DKG) Finalize(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg4(parseList(msgs)))
}

// Close releases the native state.
func (s *DKLS23DKG) Close() {
	s.state.Free()
}

// ---------- DKLs23: signing ----------

// DKLS23Signer is one party's DKLs23 signing session. DKLs23 signs with
// exactly threshold parties. It must be released with Close.
type DKLS23Signer struct {
	state *dkls23.DSGState
}

// NewDKLS23Signer starts signing with keyshare for the BIP32 child at
// derivationPath ("m" for the root key).
func NewDKLS23Signer(keyshare RawMsg, derivationPath string) (*DKLS23Signer, error) {
	state, err := dkls23.NewDSGState(string(keyshare), derivationPath)
	if err != nil {
		return nil, err
	}
	return &DKLS23Signer{state: state}, nil
}

// Round1 returns the message to broadcast to the other signers.
func (s *DKLS23Signer) Round1() (RawMsg, error) {
	return wrap(s.state.GenerateMsg1())
}

// Round2 takes the other signers' Round1 messages and returns an array of
// point-to-point messages.
func (s *DKLS23Signer) Round2(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg1(parseList(msgs)))
}

// Round3 takes the Round2 messages addressed to this signer and returns an
// array of point-to-point messages.
func (s *DKLS23Signer) Round3(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg2(parseList(msgs)))
}

// Presign takes the Round3 messages addressed to this signer and returns a
// single-use presignature handle.
func (s *DKLS23Signer) Presign(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg3(parseList(msgs)))
}

// Close releases the native state.
func (s *DKLS23Signer) Close() {
	s.state.Free()
}

// DKLS23Partial is a signer's contribution to a signature: Partial stays with
// the combining party, Msg4 is sent to it.
type DKLS23Partial struct {
	Partial RawMsg `json:"partial"`
	Msg4    RawMsg `json:"msg4"`
}

// CreateDKLS23Partial signs the 32-byte messageHash with a presignature. The
// presignature is consumed even if the call fails.
func CreateDKLS23Partial(presignature RawMsg, messageHash [32]byte) (*DKLS23Partial, error) {
	res, err := dkls23.CreatePartialSignature(string(presignature), messageHash)
	if err != nil {
		return nil, err
	}
	var out DKLS23Partial
	if err := json.Unmarshal([]byte(res), &out); err != nil {
		return nil, errors.New("sdk: parse partial signature: " + err.Error())
	}
	return &out, nil
}

// CombineDKLS23 combines the local partial signature with the other signers'
// Msg4 values and returns the hex-encoded 64-byte signature r || s.
func CombineDKLS23(partial RawMsg, msg4 []RawMsg) (string, error) {
	return dkls23.CombineSignatures(string(partial), parseList(msg4))
}

// DeriveDKLS23Public returns {"derived_public_key": "<hex>"} for the BIP32
// child at derivationPath.
func DeriveDKLS23Public(keyshare RawMsg, derivationPath string) (string, error) {
	return dkls23.DerivePublicKey(string(keyshare), derivationPath)
}

// ---------- FROST: key generation ----------

// FrostDKG is one party's FROST key generation. It must be released with
// Close.
type FrostDKG struct {
	state *frost.DKGState
}

// NewFrostDKG starts key generation for partyID (1-based) of a
// threshold-of-parties key.
func NewFrostDKG(partyID uint8, parties, threshold int) (*FrostDKG, error) {
	state, err := frost.NewDKGState(partyID, parties, threshold)
	if err != nil {
		return nil, err
	}
	return &FrostDKG{state: state}, nil
}

// Round1 returns the message to broadcast.
func (s *FrostDKG) Round1() (RawMsg, error) {
	return wrap(s.state.GenerateMsg1())
}

// Round2 takes the other parties' Round1 messages and returns an array of
// point-to-point packets; packet "to_id" values are 0-based.
func (s *FrostDKG) Round2(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg1(parseList(msgs)))
}

// Round3 takes the Round2 packets addressed to this party and returns the
// keyshare.
func (s *FrostDKG) Round3(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg2(parseList(msgs)))
}

// Finalize returns the keyshare produced by Round3.
func (s *FrostDKG) Finalize() (RawMsg, error) {
	return wrap(s.state.Finalize())
}

// Close releases the native state.
func (s *FrostDKG) Close() {
	if s.state != nil {
		s.state.Free()
	}
}

// ---------- FROST: signing ----------

// FrostSigner is one party's FROST signing session. It must be released with
// Close.
//
// FROST signing has two rounds: Round1 returns the nonce commitments to
// broadcast and Round2 returns this signer's signature share. Combine the
// shares with CombineFrost. Round3, Round4 and CreateFrostPartial exist for
// symmetry with the DKLs23 API.
type FrostSigner struct {
	state *frost.SigningState
}

// NewFrostSigner starts signing of the 32-byte messageHash with keyshare.
func NewFrostSigner(keyshare RawMsg, messageHash [32]byte) (*FrostSigner, error) {
	state, err := frost.NewSigningState(string(keyshare), messageHash)
	if err != nil {
		return nil, err
	}
	return &FrostSigner{state: state}, nil
}

// Round1 returns the nonce commitments to broadcast.
func (s *FrostSigner) Round1() (RawMsg, error) {
	return wrap(s.state.GenerateMsg1())
}

// Round2 takes the other signers' commitments and returns this signer's
// signature share.
func (s *FrostSigner) Round2(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg1(parseList(msgs)))
}

// Round3 returns an empty JSON object; FROST has no third round.
func (s *FrostSigner) Round3() (RawMsg, error) {
	return wrap(s.state.GenerateMsg2())
}

// Round4 returns an empty JSON object; FROST has no fourth round.
func (s *FrostSigner) Round4(msgs []RawMsg) (RawMsg, error) {
	return wrap(s.state.HandleMsg2(parseList(msgs)))
}

// Close releases the native state.
func (s *FrostSigner) Close() {
	if s.state != nil {
		s.state.Free()
	}
}

// FrostPartial mirrors DKLS23Partial. For FROST both fields hold the
// signature share returned by FrostSigner.Round2.
type FrostPartial struct {
	Partial RawMsg `json:"partial"`
	Msg2    RawMsg `json:"msg2"`
}

// CreateFrostPartial wraps a signature share returned by FrostSigner.Round2.
func CreateFrostPartial(share RawMsg, messageHash [32]byte) (*FrostPartial, error) {
	res, err := frost.CreatePartialSignature(string(share), messageHash)
	if err != nil {
		return nil, err
	}
	raw, err := toRaw(res)
	if err != nil {
		return nil, err
	}
	return &FrostPartial{Partial: raw, Msg2: raw}, nil
}

// CombineFrost aggregates the local signature share with the other signers'
// shares and returns the hex-encoded 64-byte Ed25519 signature.
func CombineFrost(partial RawMsg, msgList []RawMsg) (string, error) {
	return frost.CombineSignatures(string(partial), parseList(msgList))
}

// DeriveFrostPublic returns {"derived_public_key": "<hex>"} with the group
// public key.
func DeriveFrostPublic(keyshare RawMsg, derivationPath string) (string, error) {
	return frost.DerivePublicKey(string(keyshare), derivationPath)
}
