package threshold

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// InMemoryTransport is a MessageTransport that keeps all messages in memory.
// It lets several sessions in one process talk to each other and is intended
// for tests and local simulations.
type InMemoryTransport struct {
	// messages is indexed by session ID, round and recipient; broadcasts are
	// stored under BroadcastPartyID.
	messages map[string]map[int]map[uint8][]Message

	// notifications wakes up receivers waiting on a (session, round).
	notifications map[string]map[int]chan struct{}

	mu      sync.RWMutex
	timeout time.Duration
}

// NewInMemoryTransport creates an empty in-memory transport with a 30 second
// receive timeout.
func NewInMemoryTransport() *InMemoryTransport {
	return &InMemoryTransport{
		messages:      make(map[string]map[int]map[uint8][]Message),
		notifications: make(map[string]map[int]chan struct{}),
		timeout:       defaultTimeout,
	}
}

// SendMessage stores a point-to-point message for toPartyID.
func (t *InMemoryTransport) SendMessage(sessionID string, round int, toPartyID uint8, message Message) error {
	t.store(sessionID, round, toPartyID, message)
	return nil
}

// BroadcastMessage stores a message visible to every party.
func (t *InMemoryTransport) BroadcastMessage(sessionID string, round int, message Message) error {
	t.store(sessionID, round, BroadcastPartyID, message)
	return nil
}

func (t *InMemoryTransport) store(sessionID string, round int, to uint8, message Message) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.messages[sessionID] == nil {
		t.messages[sessionID] = make(map[int]map[uint8][]Message)
	}
	if t.messages[sessionID][round] == nil {
		t.messages[sessionID][round] = make(map[uint8][]Message)
	}
	t.messages[sessionID][round][to] = append(t.messages[sessionID][round][to], message)
	t.notifyWaiters(sessionID, round)
}

// ReceiveMessages blocks until at least expectedCount messages (broadcast and
// point-to-point, for any recipient) are stored for the round, then returns
// all of them.
func (t *InMemoryTransport) ReceiveMessages(sessionID string, round int, expectedCount int) ([]Message, error) {
	t.mu.Lock()
	notify := t.notifyChan(sessionID, round)
	timeout := t.timeout
	t.mu.Unlock()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		if messages := t.getMessagesForRound(sessionID, round); len(messages) >= expectedCount {
			return messages, nil
		}
		select {
		case <-deadline.C:
			return nil, fmt.Errorf("timeout waiting for round %d messages", round)
		case <-ticker.C:
		case <-notify:
		}
	}
}

// SetTimeout sets the maximum time ReceiveMessages blocks.
func (t *InMemoryTransport) SetTimeout(timeout time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.timeout = timeout
}

// GetAllMessages returns a copy of every message of a session, indexed by
// round and recipient. It is intended for debugging.
func (t *InMemoryTransport) GetAllMessages(sessionID string) map[int]map[uint8][]Message {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.messages[sessionID] == nil {
		return nil
	}
	result := make(map[int]map[uint8][]Message)
	for round, roundMsgs := range t.messages[sessionID] {
		result[round] = make(map[uint8][]Message)
		for partyID, msgs := range roundMsgs {
			result[round][partyID] = append([]Message(nil), msgs...)
		}
	}
	return result
}

// ClearSession removes all messages of a session.
func (t *InMemoryTransport) ClearSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.messages, sessionID)
	delete(t.notifications, sessionID)
}

// getMessagesForRound returns the broadcasts of a round followed by its
// point-to-point messages.
func (t *InMemoryTransport) getMessagesForRound(sessionID string, round int) []Message {
	t.mu.RLock()
	defer t.mu.RUnlock()

	roundMsgs := t.messages[sessionID][round]
	if roundMsgs == nil {
		return nil
	}
	messages := append([]Message(nil), roundMsgs[BroadcastPartyID]...)
	for partyID, msgs := range roundMsgs {
		if partyID != BroadcastPartyID {
			messages = append(messages, msgs...)
		}
	}
	return messages
}

// notifyChan returns the wake-up channel of a (session, round). t.mu must be
// held for writing.
func (t *InMemoryTransport) notifyChan(sessionID string, round int) chan struct{} {
	if t.notifications[sessionID] == nil {
		t.notifications[sessionID] = make(map[int]chan struct{})
	}
	ch := t.notifications[sessionID][round]
	if ch == nil {
		ch = make(chan struct{}, 1)
		t.notifications[sessionID][round] = ch
	}
	return ch
}

// notifyWaiters signals a receiver without blocking. Receivers also poll, so
// a dropped signal only delays them. t.mu must be held for writing.
func (t *InMemoryTransport) notifyWaiters(sessionID string, round int) {
	select {
	case t.notifyChan(sessionID, round) <- struct{}{}:
	default:
	}
}

// ========================================================================
// Multi-party coordinator
// ========================================================================

// MultiPartyCoordinator runs the DKG of several parties concurrently in one
// process over an InMemoryTransport. It is intended for tests and demos.
type MultiPartyCoordinator struct {
	transport *InMemoryTransport
	sessions  []*DKGSession
}

// NewMultiPartyCoordinator creates one DKG session per party ID, all sharing
// a session ID and an in-memory transport.
func NewMultiPartyCoordinator(partyIDs []uint8, threshold int, algorithm SignatureAlgorithm) (*MultiPartyCoordinator, error) {
	transport := NewInMemoryTransport()
	sessionID := fmt.Sprintf("multiparty-dkg-%d", time.Now().UnixNano())

	c := &MultiPartyCoordinator{transport: transport}
	for _, partyID := range partyIDs {
		session, err := NewDKGSession(partyID, partyIDs, threshold, algorithm)
		if err != nil {
			c.Free()
			return nil, fmt.Errorf("failed to create session for party %d: %w", partyID, err)
		}
		session.SetSessionID(sessionID)
		session.SetTransport(transport)
		c.sessions = append(c.sessions, session)
	}
	return c, nil
}

// ExecuteDistributedDKG runs the DKG of all parties concurrently and returns
// the keyshares in the order of the party IDs given to the constructor.
func (c *MultiPartyCoordinator) ExecuteDistributedDKG() ([]*KeyShare, error) {
	type result struct {
		index    int
		keyshare *KeyShare
		err      error
	}

	results := make(chan result, len(c.sessions))
	for i, session := range c.sessions {
		go func() {
			keyshare, err := session.ExecuteDKG()
			results <- result{index: i, keyshare: keyshare, err: err}
		}()
	}

	keyshares := make([]*KeyShare, len(c.sessions))
	var errs []string
	for range c.sessions {
		res := <-results
		if res.err != nil {
			errs = append(errs, fmt.Sprintf("party %d: %v", c.sessions[res.index].PartyID, res.err))
			continue
		}
		keyshares[res.index] = res.keyshare
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("distributed DKG failed: %s", strings.Join(errs, "; "))
	}
	return keyshares, nil
}

// GetSessions returns the DKG sessions.
func (c *MultiPartyCoordinator) GetSessions() []*DKGSession {
	return c.sessions
}

// GetTransport returns the shared transport.
func (c *MultiPartyCoordinator) GetTransport() *InMemoryTransport {
	return c.transport
}

// Free releases the resources of all sessions.
func (c *MultiPartyCoordinator) Free() {
	for _, session := range c.sessions {
		session.Free()
	}
}
