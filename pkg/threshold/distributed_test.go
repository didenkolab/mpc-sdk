package threshold

import (
	"crypto/sha256"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/didenkolab/mpc-sdk/pkg/dkls23"
)

func TestDKGAndSigning(t *testing.T) {
	tests := []struct {
		n, threshold int
		signerSets   [][]int
	}{
		{2, 2, [][]int{{0, 1}, {1, 0}}},
		{3, 2, [][]int{{0, 1}, {1, 2}, {2, 0}, {0, 1, 2}}},
		{3, 3, [][]int{{0, 1, 2}, {2, 1, 0}}},
		{4, 3, [][]int{{0, 2, 3}}},
	}
	manager := NewThresholdManager()
	for _, alg := range algorithms {
		op, err := manager.GetOperation(alg)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range tests {
			t.Run(fmt.Sprintf("%s/%d-of-%d", alg, tc.threshold, tc.n), func(t *testing.T) {
				shares := demoKeys(t, alg, tc.n, tc.threshold)
				for _, signers := range tc.signerSets {
					msg := []byte(fmt.Sprintf("message for signers %v", signers))
					sig, err := op.SignMessage(msg, shares, signers)
					if err != nil {
						t.Fatalf("signers %v: %v", signers, err)
					}
					verifyIndependently(t, sig, shares[0].PublicKey, sha256.Sum256(msg))

					ok, err := op.VerifySignature(msg, sig)
					if err != nil || !ok {
						t.Fatalf("signers %v: VerifySignature = %v, %v", signers, ok, err)
					}
					ok, err = op.VerifySignature([]byte("another message"), sig)
					if err != nil || ok {
						t.Fatalf("signers %v: signature verified for another message (%v, %v)", signers, ok, err)
					}
				}
			})
		}
	}
}

// TestMultiPartyCoordinator_DKLS23_3of3 is a regression test: a party used to
// receive its own msg4 broadcast in place of a peer's and fail with
// "MissingMessage" when it finished round 4 first.
func TestMultiPartyCoordinator_DKLS23_3of3(t *testing.T) {
	for i := range 5 {
		coordinator, err := NewMultiPartyCoordinator([]uint8{0, 1, 2}, 3, ECDSASecp256k1)
		if err != nil {
			t.Fatal(err)
		}
		shares, err := coordinator.ExecuteDistributedDKG()
		coordinator.Free()
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		checkShares(t, shares, 3, 3)
	}
}

// TestDKGSessionsWithSkewedStart runs each party in its own goroutine with a
// random start delay, so parties reach every round in different orders.
func TestDKGSessionsWithSkewedStart(t *testing.T) {
	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			ids := []uint8{2, 0, 1} // order must not matter
			transport := NewInMemoryTransport()
			sessionID := "skewed-" + alg.String()

			shares := make([]*KeyShare, len(ids))
			errs := make([]error, len(ids))
			var wg sync.WaitGroup
			for _, id := range ids {
				session, err := NewDKGSession(id, ids, 2, alg)
				if err != nil {
					t.Fatal(err)
				}
				defer session.Free()
				session.SetSessionID(sessionID)
				session.SetTransport(transport)
				session.SetTimeout(20 * time.Second)

				wg.Add(1)
				go func() {
					defer wg.Done()
					time.Sleep(time.Duration(rand.IntN(200)) * time.Millisecond)
					shares[id], errs[id] = session.ExecuteDKG()
				}()
			}
			wg.Wait()
			for id, err := range errs {
				if err != nil {
					t.Fatalf("party %d: %v", id, err)
				}
			}
			checkShares(t, shares, 3, 2)
		})
	}
}

func TestRankedDKGSession(t *testing.T) {
	ranks := []uint8{0, 1, 1}
	transport := NewInMemoryTransport()
	shares := make([]*KeyShare, len(ranks))
	errs := make([]error, len(ranks))
	var wg sync.WaitGroup
	for i := range ranks {
		session, err := NewDKGSessionWithRanks(uint8(i), ranks, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Free()
		session.SetSessionID("ranked")
		session.SetTransport(transport)
		wg.Add(1)
		go func() {
			defer wg.Done()
			shares[i], errs[i] = session.ExecuteDKG()
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("party %d: %v", i, err)
		}
	}
	checkShares(t, shares, 3, 2)

	msg := []byte("ranked signing")
	sig, err := NewDKLS23BusinessOperation().SignMessage(msg, shares, []int{0, 2})
	if err != nil {
		t.Fatal(err)
	}
	verifyIndependently(t, sig, shares[0].PublicKey, sha256.Sum256(msg))
}

func TestDKLS23ChildKeyDerivation(t *testing.T) {
	shares := demoKeys(t, ECDSASecp256k1, 3, 2)
	op := NewDKLS23BusinessOperation()
	wm := NewWalletManagerWithMode(ECDSASecp256k1, ExecutionModeInMemoryDemo)

	rootAddr, err := wm.GenerateAddress(shares[0], "eth")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{rootAddr.Address: true}

	for _, path := range []string{"m/0", "m/44/60/0/0/0", "m/44/60/0/0/1"} {
		t.Run(path, func(t *testing.T) {
			children := make([]*KeyShare, len(shares))
			for i, ks := range shares {
				child, err := op.DeriveChildKey(ks, path)
				if err != nil {
					t.Fatalf("party %d: %v", i, err)
				}
				if child.Path != path || child.PartyID != ks.PartyID || child.Threshold != ks.Threshold {
					t.Fatalf("party %d: unexpected child metadata %+v", i, child)
				}
				children[i] = child
			}
			want, err := dkls23.DeriveChildPublicKey(shares[0].KeyData, path)
			if err != nil {
				t.Fatal(err)
			}
			for i, c := range children {
				if !equalHex(c.PublicKey, want) {
					t.Fatalf("party %d child key %s, want %s", i, c.PublicKey, want)
				}
			}
			if equalHex(want, shares[0].PublicKey) {
				t.Fatal("child key equals root key")
			}

			addr, err := wm.GenerateAddress(children[0], "eth")
			if err != nil {
				t.Fatal(err)
			}
			if seen[addr.Address] {
				t.Fatalf("address %s reused", addr.Address)
			}
			seen[addr.Address] = true
			if addr.Path != path {
				t.Fatalf("address path %q, want %q", addr.Path, path)
			}

			msg := []byte("child " + path)
			sig, err := op.SignMessage(msg, children, []int{1, 2})
			if err != nil {
				t.Fatal(err)
			}
			verifyIndependently(t, sig, want, sha256.Sum256(msg))

			// Re-deriving from a child uses the same absolute path semantics.
			again, err := op.DeriveChildKey(children[0], path)
			if err != nil || !equalHex(again.PublicKey, want) {
				t.Fatalf("re-derivation from child: %v, %v", again, err)
			}
		})
	}
}

func TestDeriveChildKeyErrors(t *testing.T) {
	ecdsaShares := demoKeys(t, ECDSASecp256k1, 2, 2)
	frostShares := demoKeys(t, Ed25519FROST, 2, 2)
	dk, fr := NewDKLS23BusinessOperation(), NewFROSTBusinessOperation()

	tests := []struct {
		name string
		op   BusinessOperation
		ks   *KeyShare
		path string
	}{
		{"dkls23 nil share", dk, nil, "m"},
		{"dkls23 wrong algorithm", dk, frostShares[0], "m/0"},
		{"dkls23 empty path", dk, ecdsaShares[0], ""},
		{"dkls23 relative path", dk, ecdsaShares[0], "0/1"},
		{"dkls23 malformed path", dk, ecdsaShares[0], "m/x"},
		{"frost nil share", fr, nil, "m"},
		{"frost wrong algorithm", fr, ecdsaShares[0], "m/0"},
		{"frost relative path", fr, frostShares[0], "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.op.DeriveChildKey(tc.ks, tc.path); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	// FROST root derivation is the identity; child paths are not supported
	// and must not silently return the parent key.
	root, err := fr.DeriveChildKey(frostShares[0], "m")
	if err != nil || root.PublicKey != frostShares[0].PublicKey {
		t.Fatalf("FROST root derivation: %+v, %v", root, err)
	}
	child, err := fr.DeriveChildKey(frostShares[0], "m/0'")
	if err == nil {
		if equalHex(child.PublicKey, frostShares[0].PublicKey) {
			t.Fatal("FROST child derivation returned the parent key")
		}
	} else if !strings.Contains(err.Error(), ErrDerivationUnsupported.Error()) {
		t.Fatalf("unexpected FROST derivation error: %v", err)
	}
}

func TestSignMessageErrors(t *testing.T) {
	ecdsa := demoKeys(t, ECDSASecp256k1, 3, 2)
	other := demoKeys(t, ECDSASecp256k1, 3, 2)
	frostShares := demoKeys(t, Ed25519FROST, 3, 2)
	mixed := []*KeyShare{ecdsa[0], other[1], ecdsa[2]}

	tests := []struct {
		name    string
		alg     SignatureAlgorithm
		shares  []*KeyShare
		signers []int
		wantErr string
	}{
		{"no shares", ECDSASecp256k1, nil, []int{0, 1}, "no key shares"},
		{"insufficient signers", ECDSASecp256k1, ecdsa, []int{0}, "insufficient signers"},
		{"index out of range", ECDSASecp256k1, ecdsa, []int{0, 3}, "out of range"},
		{"negative index", ECDSASecp256k1, ecdsa, []int{-1, 0}, "out of range"},
		{"duplicate index", ECDSASecp256k1, ecdsa, []int{1, 1}, "duplicate signer"},
		{"wrong algorithm", ECDSASecp256k1, frostShares, []int{0, 1}, "wrong algorithm"},
		{"different keys", ECDSASecp256k1, mixed, []int{0, 1}, "different keys"},
		{"duplicate party", ECDSASecp256k1, []*KeyShare{ecdsa[0], ecdsa[0], ecdsa[1]}, []int{0, 1}, "duplicate party"},
		{"nil share", ECDSASecp256k1, []*KeyShare{ecdsa[0], nil}, []int{0, 1}, "is nil"},
		{"zero threshold", ECDSASecp256k1, []*KeyShare{{Algorithm: ECDSASecp256k1}}, []int{0}, "invalid threshold"},
		{"frost insufficient", Ed25519FROST, frostShares, []int{2}, "insufficient signers"},
		{"frost wrong algorithm", Ed25519FROST, ecdsa, []int{0, 1}, "wrong algorithm"},
	}
	manager := NewThresholdManager()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			op, err := manager.GetOperation(tc.alg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = op.SignMessage([]byte("x"), tc.shares, tc.signers)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}

	// A corrupted keyshare is reported, not ignored.
	broken := *ecdsa[1]
	broken.KeyData = "{}"
	if _, err := NewDKLS23BusinessOperation().SignMessage([]byte("x"), []*KeyShare{ecdsa[0], &broken}, []int{0, 1}); err == nil {
		t.Fatal("expected an error for a corrupted keyshare")
	}
}

func TestVerifySignatureErrors(t *testing.T) {
	shares := demoKeys(t, ECDSASecp256k1, 2, 2)
	op := NewDKLS23BusinessOperation()
	msg := []byte("verify")
	sig, err := op.SignMessage(msg, shares, []int{0, 1})
	if err != nil {
		t.Fatal(err)
	}

	mutate := func(f func(*Signature)) *Signature {
		c := *sig
		c.Data = append([]byte(nil), sig.Data...)
		f(&c)
		return &c
	}
	tests := []struct {
		name    string
		sig     *Signature
		valid   bool
		wantErr bool
	}{
		{"valid", sig, true, false},
		{"valid from data only", mutate(func(s *Signature) { s.R, s.S = "", "" }), true, false},
		{"tampered s", mutate(func(s *Signature) { s.S = strings.Repeat("11", 32) }), false, false},
		{"zero r", mutate(func(s *Signature) { s.R = strings.Repeat("00", 32) }), false, false},
		{"r overflows order", mutate(func(s *Signature) { s.R = strings.Repeat("ff", 32) }), false, false},
		{"nil", nil, false, true},
		{"wrong algorithm", mutate(func(s *Signature) { s.Algorithm = Ed25519FROST }), false, true},
		{"bad public key hex", mutate(func(s *Signature) { s.PublicKey = "zz" }), false, true},
		{"uncompressed length", mutate(func(s *Signature) { s.PublicKey = strings.Repeat("04", 65) }), false, true},
		{"invalid point", mutate(func(s *Signature) { s.PublicKey = "02" + strings.Repeat("00", 32) }), false, true},
		{"missing r/s", mutate(func(s *Signature) { s.R, s.S, s.Data = "", "", nil }), false, true},
		{"bad r hex", mutate(func(s *Signature) { s.R = "xy" }), false, true},
		{"bad s hex", mutate(func(s *Signature) { s.S = "xy" }), false, true},
		{"short r", mutate(func(s *Signature) { s.R = "01" }), false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := op.VerifySignature(msg, tc.sig)
			if (err != nil) != tc.wantErr || valid != tc.valid {
				t.Fatalf("got (%v, %v), want valid=%v err=%v", valid, err, tc.valid, tc.wantErr)
			}
		})
	}

	fr := NewFROSTBusinessOperation()
	if _, err := fr.VerifySignature(msg, nil); err == nil {
		t.Error("FROST: expected error for nil signature")
	}
	if _, err := fr.VerifySignature(msg, sig); err == nil {
		t.Error("FROST: expected error for ECDSA signature")
	}
}

func TestNewDKGSessionValidation(t *testing.T) {
	tests := []struct {
		name      string
		partyID   uint8
		ids       []uint8
		threshold int
		alg       SignatureAlgorithm
	}{
		{"party not listed", 3, []uint8{0, 1, 2}, 2, ECDSASecp256k1},
		{"duplicate ids", 0, []uint8{0, 0, 1}, 2, ECDSASecp256k1},
		{"ids not contiguous", 0, []uint8{0, 2}, 2, ECDSASecp256k1},
		{"single party", 0, []uint8{0}, 1, ECDSASecp256k1},
		{"threshold zero", 0, []uint8{0, 1}, 0, ECDSASecp256k1},
		{"threshold above n", 0, []uint8{0, 1}, 3, ECDSASecp256k1},
		{"dkls23 threshold one", 0, []uint8{0, 1}, 1, ECDSASecp256k1},
		{"frost threshold one", 0, []uint8{0, 1}, 1, Ed25519FROST},
		{"unknown algorithm", 0, []uint8{0, 1}, 2, SignatureAlgorithm(42)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewDKGSession(tc.partyID, tc.ids, tc.threshold, tc.alg)
			if err == nil {
				s.Free()
				t.Fatal("expected an error")
			}
		})
	}

	rankedTests := []struct {
		name      string
		partyID   uint8
		ranks     []uint8
		threshold int
	}{
		{"empty", 0, nil, 2},
		{"party out of range", 3, []uint8{0, 1, 1}, 2},
		{"rank too high", 0, []uint8{0, 2, 2}, 2},
	}
	for _, tc := range rankedTests {
		t.Run("ranked "+tc.name, func(t *testing.T) {
			s, err := NewDKGSessionWithRanks(tc.partyID, tc.ranks, tc.threshold)
			if err == nil {
				s.Free()
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDKGSessionLifecycle(t *testing.T) {
	s, err := NewDKGSession(0, []uint8{0, 1}, 2, ECDSASecp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Free()

	if s.GetCurrentRound() != RoundInit || s.IsCompleted() {
		t.Fatal("new session must be at RoundInit and not completed")
	}
	if _, err := s.GetKeyshare(); err == nil {
		t.Fatal("GetKeyshare must fail before completion")
	}
	if _, err := s.ExecuteDKG(); err == nil || !strings.Contains(err.Error(), "transport not set") {
		t.Fatalf("ExecuteDKG without transport: %v", err)
	}

	s.SetSessionID("lonely")
	if s.GetSessionID() != "lonely" {
		t.Fatalf("session ID %q", s.GetSessionID())
	}
	s.SetTransport(NewInMemoryTransport())
	s.SetTimeout(200 * time.Millisecond)

	// The peer never shows up: the session times out and stays failed.
	_, err = s.ExecuteDKG()
	if err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout, got %v", err)
	}
	if s.GetCurrentRound() != Round2 {
		t.Fatalf("failed in round %d, want %d", s.GetCurrentRound(), Round2)
	}
	if _, err := s.ExecuteDKG(); err == nil || !strings.Contains(err.Error(), "already failed") {
		t.Fatalf("second ExecuteDKG: %v", err)
	}

	s.Free()
	s.Free() // idempotent

	freed, err := NewDKGSession(1, []uint8{0, 1}, 2, Ed25519FROST)
	if err != nil {
		t.Fatal(err)
	}
	freed.SetTransport(NewInMemoryTransport())
	freed.Free()
	if _, err := freed.ExecuteDKG(); err == nil || !strings.Contains(err.Error(), "freed") {
		t.Fatalf("ExecuteDKG after Free: %v", err)
	}
}

func TestCompletedSessionReturnsSameKeyshare(t *testing.T) {
	coordinator, err := NewMultiPartyCoordinator([]uint8{0, 1}, 2, ECDSASecp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer coordinator.Free()
	shares, err := coordinator.ExecuteDistributedDKG()
	if err != nil {
		t.Fatal(err)
	}
	if coordinator.GetTransport() == nil || len(coordinator.GetSessions()) != 2 {
		t.Fatal("coordinator accessors")
	}
	s := coordinator.GetSessions()[1]
	if !s.IsCompleted() || s.GetCurrentRound() != RoundCompleted {
		t.Fatal("session should be completed")
	}
	again, err := s.ExecuteDKG()
	if err != nil || again != shares[1] {
		t.Fatalf("ExecuteDKG after completion: %v, %v", again, err)
	}
	got, err := s.GetKeyshare()
	if err != nil || got != shares[1] {
		t.Fatalf("GetKeyshare: %v, %v", got, err)
	}
}

func TestMultiPartyCoordinatorErrors(t *testing.T) {
	if _, err := NewMultiPartyCoordinator([]uint8{0, 1, 5}, 2, ECDSASecp256k1); err == nil {
		t.Fatal("expected error for invalid party IDs")
	}
}

// TestProtocolErrorsAreReported injects a malformed peer message.
func TestProtocolErrorsAreReported(t *testing.T) {
	transport := NewInMemoryTransport()
	s, err := NewDKGSession(0, []uint8{0, 1}, 2, ECDSASecp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Free()
	s.SetSessionID("bad-peer")
	s.SetTransport(transport)
	s.SetTimeout(2 * time.Second)

	if err := transport.BroadcastMessage("bad-peer", int(Round1), Message{
		FromPartyID: 1, ToPartyID: BroadcastPartyID, Round: int(Round1), Data: []byte(`{"bogus":true}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteDKG(); err == nil || !strings.Contains(err.Error(), "handle msg1") {
		t.Fatalf("expected msg1 error, got %v", err)
	}
}

func TestConflictingMessagesAreRejected(t *testing.T) {
	transport := NewInMemoryTransport()
	s, err := NewDKGSession(0, []uint8{0, 1, 2}, 2, ECDSASecp256k1)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Free()
	s.SetSessionID("equivocation")
	s.SetTransport(transport)
	for _, data := range []string{`{"a":1}`, `{"a":2}`} {
		if err := transport.BroadcastMessage("equivocation", int(Round1), Message{
			FromPartyID: 1, ToPartyID: BroadcastPartyID, Data: []byte(data),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ExecuteDKG(); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("expected conflicting-message error, got %v", err)
	}
}
