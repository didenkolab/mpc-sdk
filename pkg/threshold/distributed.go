package threshold

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/didenkolab/mpc-sdk/pkg/dkls23"
	"github.com/didenkolab/mpc-sdk/pkg/frost"
)

// Distributed key generation.
//
// Each party creates its own DKGSession with the same participant list and
// session ID, attaches a MessageTransport and calls ExecuteDKG. Protocol
// messages are exchanged only through the transport, so parties may live in
// different processes or on different machines, and every party ends up with
// its own keyshare only:
//
//	session, err := threshold.NewDKGSession(myID, []uint8{0, 1, 2}, 2, threshold.ECDSASecp256k1)
//	if err != nil { ... }
//	defer session.Free()
//	session.SetSessionID(sharedSessionID)
//	session.SetTransport(transport)
//	keyshare, err := session.ExecuteDKG()

// BroadcastPartyID is the Message.ToPartyID value used for broadcast messages.
const BroadcastPartyID uint8 = 0xFF

// defaultTimeout bounds how long a session waits for the messages of a round.
const defaultTimeout = 30 * time.Second

// DKGSession runs distributed key generation for one local party.
type DKGSession struct {
	PartyID   uint8
	PartyIDs  []uint8 // all participants, sorted, including PartyID
	Threshold int
	Algorithm SignatureAlgorithm

	dkgState  interface{} // *dkls23.DKGState or *frost.DKGState
	round     int
	completed bool
	failed    error
	keyshare  *KeyShare

	transport   MessageTransport
	sessionID   string
	commitment2 string

	mu      sync.RWMutex
	timeout time.Duration
}

// MessageTransport delivers protocol messages between the parties of a
// session.
//
// ReceiveMessages must return every message stored for (sessionID, round) —
// broadcasts as well as point-to-point messages, possibly including the
// caller's own and those addressed to other parties — once at least
// expectedCount of them are available, or an error on timeout. Sessions
// filter the result by sender and recipient themselves and call
// ReceiveMessages again with a larger expectedCount when they still miss
// messages, so a transport may also return only the messages visible to the
// local party.
type MessageTransport interface {
	// SendMessage sends a point-to-point message to toPartyID.
	SendMessage(sessionID string, round int, toPartyID uint8, message Message) error

	// BroadcastMessage sends a message to all parties.
	BroadcastMessage(sessionID string, round int, message Message) error

	// ReceiveMessages blocks until at least expectedCount messages are
	// available for the round and returns them.
	ReceiveMessages(sessionID string, round int, expectedCount int) ([]Message, error)

	// SetTimeout sets the maximum time ReceiveMessages may block.
	SetTimeout(timeout time.Duration)
}

// Message is a protocol message exchanged between parties.
type Message struct {
	FromPartyID uint8           `json:"from_party_id"`
	ToPartyID   uint8           `json:"to_party_id"` // BroadcastPartyID for broadcasts
	Round       int             `json:"round"`
	Data        json.RawMessage `json:"data"`
	Timestamp   time.Time       `json:"timestamp"`
}

// DKGRound identifies a step of the DKG protocol. It is also used as the
// round number on the transport.
type DKGRound int

// DKG rounds. FROST uses Round1 to Round3 only.
const (
	RoundInit    DKGRound = iota
	Round1                // broadcast msg1
	Round2                // handle msg1, send P2P msg2
	Round3                // handle msg2, send P2P msg3 (FROST: finalize)
	RoundCommit2          // broadcast commitment 2 (DKLs23)
	Round4                // handle msg3, broadcast msg4 (DKLs23)
	Round5                // handle msg4, produce the keyshare (DKLs23)
	RoundCompleted
)

// NewDKGSession creates a DKG session for partyID. partyIDs lists all
// participants and must be a permutation of 0..len(partyIDs)-1. threshold is
// the number of parties required to sign.
func NewDKGSession(partyID uint8, partyIDs []uint8, threshold int, algorithm SignatureAlgorithm) (*DKGSession, error) {
	ids, err := normalizePartyIDs(partyID, partyIDs)
	if err != nil {
		return nil, err
	}
	if threshold <= 0 || threshold > len(ids) {
		return nil, fmt.Errorf("invalid threshold: %d (must be 1-%d)", threshold, len(ids))
	}

	var state interface{}
	switch algorithm {
	case ECDSASecp256k1:
		st, err := dkls23.NewDKGState(partyID, len(ids), threshold)
		if err != nil {
			return nil, fmt.Errorf("failed to create DKLs23 DKG state: %w", err)
		}
		state = st
	case Ed25519FROST:
		st, err := frost.NewDKGState(frostID(partyID), len(ids), threshold)
		if err != nil {
			return nil, fmt.Errorf("failed to create FROST DKG state: %w", err)
		}
		state = st
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return newSession(partyID, ids, threshold, algorithm, state, "dkg"), nil
}

// NewDKGSessionWithRanks creates a DKLs23 session for a hierarchical key.
// ranks holds one rank per party, indexed by party ID (0..len(ranks)-1).
func NewDKGSessionWithRanks(partyID uint8, ranks []uint8, threshold int) (*DKGSession, error) {
	if len(ranks) < 2 || len(ranks) > maxParties {
		return nil, fmt.Errorf("ranks must have 2-%d entries, got %d", maxParties, len(ranks))
	}
	if int(partyID) >= len(ranks) {
		return nil, fmt.Errorf("partyID %d out of range for %d ranks", partyID, len(ranks))
	}

	state, err := dkls23.NewDKGStateWithRanks(partyID, ranks, threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to create ranked DKLs23 DKG state: %w", err)
	}

	ids := make([]uint8, len(ranks))
	for i := range ids {
		ids[i] = uint8(i)
	}
	return newSession(partyID, ids, threshold, ECDSASecp256k1, state, "dkg-ranked"), nil
}

func newSession(partyID uint8, ids []uint8, threshold int, alg SignatureAlgorithm, state interface{}, prefix string) *DKGSession {
	return &DKGSession{
		PartyID:   partyID,
		PartyIDs:  ids,
		Threshold: threshold,
		Algorithm: alg,
		dkgState:  state,
		round:     int(RoundInit),
		sessionID: fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), partyID),
		timeout:   defaultTimeout,
	}
}

// normalizePartyIDs validates partyIDs and returns a sorted copy.
func normalizePartyIDs(partyID uint8, partyIDs []uint8) ([]uint8, error) {
	n := len(partyIDs)
	if n < 2 || n > maxParties {
		return nil, fmt.Errorf("need 2-%d participants, got %d", maxParties, n)
	}
	ids := append([]uint8(nil), partyIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i, id := range ids {
		if id != uint8(i) {
			return nil, fmt.Errorf("participant IDs must be 0..%d without duplicates, got %v", n-1, partyIDs)
		}
	}
	if int(partyID) >= n {
		return nil, fmt.Errorf("partyID %d not found in participants list", partyID)
	}
	return ids, nil
}

// frostID maps a 0-based party ID to the 1-based FROST identifier.
func frostID(partyID uint8) uint8 { return partyID + 1 }

// SetSessionID sets the session ID shared by all parties.
func (s *DKGSession) SetSessionID(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionID = sessionID
}

// SetTransport sets the transport used to exchange messages.
func (s *DKGSession) SetTransport(transport MessageTransport) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.transport = transport
	if transport != nil && s.timeout > 0 {
		transport.SetTimeout(s.timeout)
	}
}

// SetTimeout sets how long the session waits for the messages of a round.
func (s *DKGSession) SetTimeout(timeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.timeout = timeout
	if s.transport != nil {
		s.transport.SetTimeout(timeout)
	}
}

// ExecuteDKG runs the whole protocol and returns the local party's keyshare.
// After success it returns the same keyshare again; after a failure the
// session is unusable and every call returns the original error.
func (s *DKGSession) ExecuteDKG() (*KeyShare, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transport == nil {
		return nil, errors.New("transport not set: call SetTransport first")
	}
	if s.completed {
		return s.keyshare, nil
	}
	if s.failed != nil {
		return nil, fmt.Errorf("DKG session already failed: %w", s.failed)
	}
	if s.dkgState == nil {
		return nil, errors.New("DKG session has been freed")
	}

	type step struct {
		name string
		run  func() error
	}
	var steps []step
	switch s.Algorithm {
	case ECDSASecp256k1:
		steps = []step{
			{"round 1", s.executeRound1},
			{"round 2", s.executeRound2},
			{"round 3", s.executeRound3},
			{"commitment2 broadcast", s.broadcastCommitment2},
			{"round 4", s.executeRound4},
			{"round 5", s.executeRound5},
		}
	case Ed25519FROST:
		steps = []step{
			{"round 1", s.executeRound1},
			{"round 2", s.executeRound2},
			{"FROST finalize", s.executeFrostFinalize},
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", s.Algorithm)
	}

	for _, step := range steps {
		if err := step.run(); err != nil {
			s.failed = fmt.Errorf("%s failed: %w", step.name, err)
			return nil, s.failed
		}
	}

	s.round = int(RoundCompleted)
	s.completed = true
	return s.keyshare, nil
}

// GetSessionID returns the session ID.
func (s *DKGSession) GetSessionID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// GetCurrentRound returns the last round the session started.
func (s *DKGSession) GetCurrentRound() DKGRound {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return DKGRound(s.round)
}

// IsCompleted reports whether the DKG finished successfully.
func (s *DKGSession) IsCompleted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.completed
}

// GetKeyshare returns the keyshare of a completed session.
func (s *DKGSession) GetKeyshare() (*KeyShare, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.completed {
		return nil, errors.New("DKG not completed yet")
	}
	return s.keyshare, nil
}

// Free releases the native DKG state. It is safe to call more than once.
func (s *DKGSession) Free() {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch state := s.dkgState.(type) {
	case *dkls23.DKGState:
		state.Free()
	case *frost.DKGState:
		state.Free()
	}
	s.dkgState = nil
}

// ========================================================================
// Message plumbing
// ========================================================================

// p2pHeader is the routing part of a point-to-point protocol message.
type p2pHeader struct {
	ToID   *int `json:"to_id"`
	FromID *int `json:"from_id"`
}

func (s *DKGSession) isPeer(id uint8) bool {
	return id != s.PartyID && int(id) < len(s.PartyIDs)
}

// collect waits for one message of the given round from every other party.
// If p2p is true only messages addressed to the local party are accepted.
// The payloads are returned ordered by sender ID.
func (s *DKGSession) collect(round DKGRound, p2p bool) ([]json.RawMessage, error) {
	want := len(s.PartyIDs) - 1
	bySender := make(map[uint8]json.RawMessage, want)
	expected := want
	for {
		msgs, err := s.transport.ReceiveMessages(s.sessionID, int(round), expected)
		if err != nil {
			return nil, fmt.Errorf("receive round %d messages: %w", round, err)
		}
		for _, m := range msgs {
			if !s.isPeer(m.FromPartyID) {
				continue
			}
			if p2p && m.ToPartyID != s.PartyID {
				continue
			}
			if prev, dup := bySender[m.FromPartyID]; dup && string(prev) != string(m.Data) {
				return nil, fmt.Errorf("conflicting round %d messages from party %d", round, m.FromPartyID)
			}
			bySender[m.FromPartyID] = m.Data
		}
		if len(bySender) >= want {
			break
		}
		// Not every message seen so far was ours: wait for more.
		if len(msgs) >= expected {
			expected = len(msgs) + 1
		}
	}

	out := make([]json.RawMessage, 0, want)
	for _, id := range s.PartyIDs {
		if data, ok := bySender[id]; ok {
			out = append(out, data)
		}
	}
	return out, nil
}

func (s *DKGSession) broadcast(round DKGRound, data json.RawMessage) error {
	return s.transport.BroadcastMessage(s.sessionID, int(round), Message{
		FromPartyID: s.PartyID,
		ToPartyID:   BroadcastPartyID,
		Round:       int(round),
		Data:        data,
		Timestamp:   time.Now(),
	})
}

// sendP2P routes every element of a JSON array of P2P messages to the party
// named by its "to_id" field. toID maps that field to a party ID.
func (s *DKGSession) sendP2P(round DKGRound, arrayJSON string, toID func(int) (uint8, error)) error {
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(arrayJSON), &items); err != nil {
		return fmt.Errorf("parse round %d output: %w", round, err)
	}
	for _, item := range items {
		var hdr p2pHeader
		if err := json.Unmarshal(item, &hdr); err != nil {
			return fmt.Errorf("parse round %d message header: %w", round, err)
		}
		if hdr.ToID == nil {
			return fmt.Errorf("round %d message has no to_id", round)
		}
		to, err := toID(*hdr.ToID)
		if err != nil {
			return err
		}
		if to == s.PartyID {
			continue
		}
		msg := Message{
			FromPartyID: s.PartyID,
			ToPartyID:   to,
			Round:       int(round),
			Data:        item,
			Timestamp:   time.Now(),
		}
		if err := s.transport.SendMessage(s.sessionID, int(round), to, msg); err != nil {
			return fmt.Errorf("send round %d message to party %d: %w", round, to, err)
		}
	}
	return nil
}

// partyIDFromWire validates a 0-based to_id taken from a protocol message.
func (s *DKGSession) partyIDFromWire(id int) (uint8, error) {
	if id < 0 || id >= len(s.PartyIDs) {
		return 0, fmt.Errorf("message addressed to unknown party %d", id)
	}
	return uint8(id), nil
}

func asList(msgs []json.RawMessage) []interface{} {
	out := make([]interface{}, len(msgs))
	for i, m := range msgs {
		out[i] = m
	}
	return out
}

// newKeyShare builds the local KeyShare from a protocol keyshare JSON.
func (s *DKGSession) newKeyShare(keyshareJSON string) (*KeyShare, error) {
	publicKey, err := keysharePublicKey(s.Algorithm, keyshareJSON)
	if err != nil {
		return nil, err
	}
	return &KeyShare{
		Algorithm:    s.Algorithm,
		PartyID:      s.PartyID,
		Participants: len(s.PartyIDs),
		Threshold:    s.Threshold,
		KeyData:      keyshareJSON,
		PublicKey:    publicKey,
		Path:         "m",
	}, nil
}

// keysharePublicKey returns the lowercase hex group public key of a
// protocol keyshare.
func keysharePublicKey(alg SignatureAlgorithm, keyshareJSON string) (string, error) {
	if alg == Ed25519FROST {
		res, err := frost.DerivePublicKey(keyshareJSON, "m")
		if err != nil {
			return "", fmt.Errorf("read FROST group key: %w", err)
		}
		return parseDerivedPublicKey(res)
	}

	var ks struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal([]byte(keyshareJSON), &ks); err != nil {
		return "", fmt.Errorf("parse keyshare: %w", err)
	}
	if ks.PublicKey == "" {
		return "", errors.New("keyshare has no public key")
	}
	return lowerHex(ks.PublicKey), nil
}

// parseDerivedPublicKey extracts the key from a {"derived_public_key": ...}
// response.
func parseDerivedPublicKey(res string) (string, error) {
	var derived struct {
		Key string `json:"derived_public_key"`
	}
	if err := json.Unmarshal([]byte(res), &derived); err != nil || derived.Key == "" {
		return "", fmt.Errorf("unexpected derive_public_key response %q", res)
	}
	return lowerHex(derived.Key), nil
}

// ========================================================================
// Rounds
// ========================================================================

// executeRound1 generates msg1 and broadcasts it.
func (s *DKGSession) executeRound1() error {
	s.round = int(Round1)

	var (
		msg1 string
		err  error
	)
	switch state := s.dkgState.(type) {
	case *dkls23.DKGState:
		msg1, err = state.GenerateMsg1()
	case *frost.DKGState:
		msg1, err = state.GenerateMsg1()
	default:
		return errors.New("unknown DKG state type")
	}
	if err != nil {
		return fmt.Errorf("generate msg1: %w", err)
	}
	return s.broadcast(Round1, json.RawMessage(msg1))
}

// executeRound2 handles the other parties' msg1 and sends the P2P msg2.
func (s *DKGSession) executeRound2() error {
	s.round = int(Round2)

	msg1, err := s.collect(Round1, false)
	if err != nil {
		return err
	}

	var msg2 string
	switch state := s.dkgState.(type) {
	case *dkls23.DKGState:
		msg2, err = state.HandleMsg1(asList(msg1))
	case *frost.DKGState:
		msg2, err = state.HandleMsg1(asList(msg1))
	default:
		return errors.New("unknown DKG state type")
	}
	if err != nil {
		return fmt.Errorf("handle msg1: %w", err)
	}
	return s.sendP2P(Round2, msg2, s.partyIDFromWire)
}

// executeRound3 handles the msg2 addressed to this party and sends the P2P
// msg3 (DKLs23 only).
func (s *DKGSession) executeRound3() error {
	s.round = int(Round3)

	state, ok := s.dkgState.(*dkls23.DKGState)
	if !ok {
		return fmt.Errorf("round 3 is not defined for %s", s.Algorithm)
	}
	msg2, err := s.collect(Round2, true)
	if err != nil {
		return err
	}
	msg3, err := state.HandleMsg2(asList(msg2))
	if err != nil {
		return fmt.Errorf("handle msg2: %w", err)
	}
	return s.sendP2P(Round3, msg3, s.partyIDFromWire)
}

// broadcastCommitment2 computes and broadcasts commitment 2 (DKLs23 only).
func (s *DKGSession) broadcastCommitment2() error {
	s.round = int(RoundCommit2)

	state, ok := s.dkgState.(*dkls23.DKGState)
	if !ok {
		return fmt.Errorf("commitment 2 is not defined for %s", s.Algorithm)
	}
	commitment, err := state.CalculateCommitment2()
	if err != nil {
		return fmt.Errorf("calculate commitment2: %w", err)
	}
	s.commitment2 = commitment

	data, err := json.Marshal(commitment)
	if err != nil {
		return err
	}
	return s.broadcast(RoundCommit2, data)
}

// executeRound4 handles the msg3 addressed to this party plus all
// commitments and broadcasts msg4 (DKLs23 only).
func (s *DKGSession) executeRound4() error {
	s.round = int(Round4)

	state, ok := s.dkgState.(*dkls23.DKGState)
	if !ok {
		return fmt.Errorf("round 4 is not defined for %s", s.Algorithm)
	}
	if s.commitment2 == "" {
		return errors.New("commitment2 not calculated locally")
	}

	msg3, err := s.collect(Round3, true)
	if err != nil {
		return err
	}
	others, err := s.collect(RoundCommit2, false)
	if err != nil {
		return err
	}

	// Commitments of all parties, including our own, ordered by party ID.
	commitments := make([]string, 0, len(s.PartyIDs))
	next := 0
	for _, id := range s.PartyIDs {
		if id == s.PartyID {
			commitments = append(commitments, s.commitment2)
			continue
		}
		var c string
		if err := json.Unmarshal(others[next], &c); err != nil {
			return fmt.Errorf("parse commitment2 from party %d: %w", id, err)
		}
		commitments = append(commitments, c)
		next++
	}

	msg4, err := state.HandleMsg3(asList(msg3), commitments)
	if err != nil {
		return fmt.Errorf("handle msg3 (DKLs23): %w", err)
	}
	return s.broadcast(Round4, json.RawMessage(msg4))
}

// executeRound5 handles the other parties' msg4 and stores the keyshare
// (DKLs23 only).
func (s *DKGSession) executeRound5() error {
	s.round = int(Round5)

	state, ok := s.dkgState.(*dkls23.DKGState)
	if !ok {
		return fmt.Errorf("round 5 is not defined for %s", s.Algorithm)
	}
	msg4, err := s.collect(Round4, false)
	if err != nil {
		return err
	}
	keyshareJSON, err := state.HandleMsg4(asList(msg4))
	if err != nil {
		return fmt.Errorf("handle msg4 (DKLs23): %w", err)
	}
	s.keyshare, err = s.newKeyShare(keyshareJSON)
	return err
}

// executeFrostFinalize handles the FROST round-2 packets addressed to this
// party and stores the keyshare.
func (s *DKGSession) executeFrostFinalize() error {
	s.round = int(Round3)

	state, ok := s.dkgState.(*frost.DKGState)
	if !ok {
		return errors.New("invalid state type for FROST finalize")
	}
	msg2, err := s.collect(Round2, true)
	if err != nil {
		return err
	}
	keyshareJSON, err := state.HandleMsg2(asList(msg2))
	if err != nil {
		return fmt.Errorf("handle FROST msg2: %w", err)
	}
	s.keyshare, err = s.newKeyShare(keyshareJSON)
	return err
}
