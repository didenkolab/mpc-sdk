package frost

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// runDKG executes a complete n-party DKG with the given threshold and returns
// the keyshare of every party, indexed by partyID-1.
func runDKG(t *testing.T, n, threshold int) []string {
	t.Helper()

	states := make([]*DKGState, n)
	for i := range states {
		s, err := NewDKGState(uint8(i+1), n, threshold)
		if err != nil {
			t.Fatalf("NewDKGState(%d): %v", i+1, err)
		}
		t.Cleanup(s.Free)
		states[i] = s
	}

	msg1 := make([]string, n)
	for i, s := range states {
		m, err := s.GenerateMsg1()
		if err != nil {
			t.Fatalf("party %d GenerateMsg1: %v", i+1, err)
		}
		msg1[i] = m
	}

	msg2 := make([]string, n)
	for i, s := range states {
		m, err := s.HandleMsg1(othersOf(msg1, i))
		if err != nil {
			t.Fatalf("party %d HandleMsg1: %v", i+1, err)
		}
		msg2[i] = m
	}

	keyshares := make([]string, n)
	for i, s := range states {
		in, err := Round2MessagesFor(uint8(i+1), msg2...)
		if err != nil {
			t.Fatalf("Round2MessagesFor(%d): %v", i+1, err)
		}
		ks, err := s.HandleMsg2(in)
		if err != nil {
			t.Fatalf("party %d HandleMsg2: %v", i+1, err)
		}
		final, err := s.Finalize()
		if err != nil {
			t.Fatalf("party %d Finalize: %v", i+1, err)
		}
		if final != ks {
			t.Fatalf("party %d: Finalize result differs from HandleMsg2 result", i+1)
		}
		keyshares[i] = ks
	}
	return keyshares
}

// othersOf returns all messages except the one at index self.
func othersOf(msgs []string, self int) []interface{} {
	out := make([]interface{}, 0, len(msgs)-1)
	for j, m := range msgs {
		if j != self {
			out = append(out, m)
		}
	}
	return out
}

// sign runs the two-round signing protocol for the given keyshares and
// returns the hex-encoded aggregated signature.
func sign(t *testing.T, keyshares []string, message []byte) string {
	t.Helper()

	signers := make([]*SigningState, len(keyshares))
	for i, ks := range keyshares {
		s, err := NewSigningStateForMessage(ks, message)
		if err != nil {
			t.Fatalf("NewSigningStateForMessage(%d): %v", i, err)
		}
		t.Cleanup(s.Free)
		signers[i] = s
	}

	commitments := make([]string, len(signers))
	for i, s := range signers {
		c, err := s.GenerateMsg1()
		if err != nil {
			t.Fatalf("signer %d GenerateMsg1: %v", i, err)
		}
		commitments[i] = c
	}

	partials := make([]string, len(signers))
	for i, s := range signers {
		share, err := s.HandleMsg1(othersOf(commitments, i))
		if err != nil {
			t.Fatalf("signer %d HandleMsg1: %v", i, err)
		}
		partial, err := CreatePartialSignature(share, HashMessage("unused"))
		if err != nil {
			t.Fatalf("signer %d CreatePartialSignature: %v", i, err)
		}
		partials[i] = partial
	}

	sig, err := CombineSignatures(partials[0], othersOf(partials, 0))
	if err != nil {
		t.Fatalf("CombineSignatures: %v", err)
	}
	return sig
}

// groupPublicKey returns the raw group public key of a keyshare.
func groupPublicKey(t *testing.T, keyshare string) ed25519.PublicKey {
	t.Helper()
	res, err := DerivePublicKey(keyshare, "m")
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	var parsed struct {
		DerivedPublicKey string `json:"derived_public_key"`
	}
	if err := json.Unmarshal([]byte(res), &parsed); err != nil {
		t.Fatalf("parse public key %q: %v", res, err)
	}
	pub, err := hex.DecodeString(parsed.DerivedPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("invalid public key %q: %v", parsed.DerivedPublicKey, err)
	}
	return pub
}

func TestDKG(t *testing.T) {
	tests := []struct {
		name         string
		n, threshold int
	}{
		{"2-of-2", 2, 2},
		{"2-of-3", 3, 2},
		{"3-of-3", 3, 3},
		{"3-of-5", 5, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyshares := runDKG(t, tc.n, tc.threshold)

			want := groupPublicKey(t, keyshares[0])
			for i, ks := range keyshares {
				var parsed struct {
					ParticipantID uint16          `json:"participant_id"`
					KeyPackage    json.RawMessage `json:"key_package"`
				}
				if err := json.Unmarshal([]byte(ks), &parsed); err != nil {
					t.Fatalf("party %d keyshare is not JSON: %v", i+1, err)
				}
				if int(parsed.ParticipantID) != i+1 {
					t.Errorf("party %d keyshare has participant_id %d", i+1, parsed.ParticipantID)
				}
				if !strings.Contains(string(parsed.KeyPackage), "signing_share") {
					t.Errorf("party %d key_package has no signing_share", i+1)
				}
				if got := groupPublicKey(t, ks); !got.Equal(want) {
					t.Errorf("party %d group key %x, want %x", i+1, got, want)
				}
			}
		})
	}
}

func TestSigning(t *testing.T) {
	keyshares := runDKG(t, 3, 2)
	pub := groupPublicKey(t, keyshares[0])
	message := []byte("FROST threshold signature test")

	tests := []struct {
		name    string
		signers []int // zero-based indexes into keyshares
	}{
		{"parties 1 and 2", []int{0, 1}},
		{"parties 1 and 3", []int{0, 2}},
		{"parties 2 and 3", []int{1, 2}},
		{"all parties", []int{0, 1, 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shares := make([]string, len(tc.signers))
			for i, idx := range tc.signers {
				shares[i] = keyshares[idx]
			}
			sigHex := sign(t, shares, message)

			sig, err := hex.DecodeString(sigHex)
			if err != nil || len(sig) != ed25519.SignatureSize {
				t.Fatalf("invalid signature %q: %v", sigHex, err)
			}
			if !ed25519.Verify(pub, message, sig) {
				t.Fatal("crypto/ed25519 rejected the threshold signature")
			}
			if ed25519.Verify(pub, []byte("tampered"), sig) {
				t.Fatal("signature verified for a different message")
			}

			ok, err := VerifySignature(hex.EncodeToString(pub), message, sigHex)
			if err != nil || !ok {
				t.Fatalf("VerifySignature(hex key) = %v, %v; want true", ok, err)
			}
			pubJSON, err := DerivePublicKey(shares[0], "m")
			if err != nil {
				t.Fatalf("DerivePublicKey: %v", err)
			}
			ok, err = VerifySignature(pubJSON, message, sigHex)
			if err != nil || !ok {
				t.Fatalf("VerifySignature(JSON key) = %v, %v; want true", ok, err)
			}
			ok, err = VerifySignature(pubJSON, []byte("tampered"), sigHex)
			if err != nil || ok {
				t.Fatalf("VerifySignature(tampered) = %v, %v; want false", ok, err)
			}
		})
	}
}

func TestSigningWithMessageHash(t *testing.T) {
	keyshares := runDKG(t, 2, 2)
	hash := HashMessage("hash-based signing")

	s1, err := NewSigningState(keyshares[0], hash)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Free()
	s2, err := NewSigningState(keyshares[1], hash)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Free()

	c1, err := s1.GenerateMsg1()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := s2.GenerateMsg1()
	if err != nil {
		t.Fatal(err)
	}
	p1, err := s1.HandleMsg1([]interface{}{c2})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s2.HandleMsg1([]interface{}{c1})
	if err != nil {
		t.Fatal(err)
	}
	sigHex, err := CombineSignatures(p1, []interface{}{p2})
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(sigHex)
	if !ed25519.Verify(groupPublicKey(t, keyshares[0]), hash[:], sig) {
		t.Fatal("signature over message hash does not verify")
	}

	// The DKLs23-compatible second round is a no-op for FROST.
	for name, fn := range map[string]func() (string, error){
		"GenerateMsg2": s1.GenerateMsg2,
		"HandleMsg2":   func() (string, error) { return s1.HandleMsg2(nil) },
	} {
		got, err := fn()
		if err != nil || got != "{}" {
			t.Errorf("%s = %q, %v; want \"{}\"", name, got, err)
		}
	}
}

func TestSigningNonceIsSingleUse(t *testing.T) {
	keyshares := runDKG(t, 2, 2)
	msg := []byte("nonce reuse")

	s1, err := NewSigningStateForMessage(keyshares[0], msg)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Free()
	s2, err := NewSigningStateForMessage(keyshares[1], msg)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Free()

	if _, err := s1.GenerateMsg1(); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.GenerateMsg1(); !errors.Is(err, ErrFFICall) {
		t.Errorf("second GenerateMsg1: got %v, want ErrFFICall", err)
	}
	c2, err := s2.GenerateMsg1()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandleMsg1([]interface{}{c2}); err != nil {
		t.Fatal(err)
	}
	if _, err := s1.HandleMsg1([]interface{}{c2}); !errors.Is(err, ErrFFICall) {
		t.Errorf("second HandleMsg1: got %v, want ErrFFICall", err)
	}

	// A failed attempt must burn the nonces as well.
	if _, err := s2.HandleMsg1([]interface{}{"not json"}); err == nil {
		t.Fatal("HandleMsg1 accepted a malformed commitment")
	}
	if _, err := s2.HandleMsg1([]interface{}{c2}); !errors.Is(err, ErrFFICall) {
		t.Errorf("HandleMsg1 after failure: got %v, want ErrFFICall", err)
	}
}

func TestNewDKGStateValidation(t *testing.T) {
	tests := []struct {
		name         string
		partyID      uint8
		n, threshold int
		wantErr      error
	}{
		{"valid 2-of-3", 1, 3, 2, nil},
		{"valid last party", 3, 3, 3, nil},
		{"party id zero", 0, 3, 2, ErrInvalidPartyID},
		{"party id above n", 4, 3, 2, ErrInvalidPartyID},
		{"threshold above n", 1, 3, 4, ErrInvalidThreshold},
		{"threshold one", 1, 3, 1, ErrInvalidThreshold},
		{"too many parties", 1, 70000, 2, ErrInvalidThreshold},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewDKGState(tc.partyID, tc.n, tc.threshold)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got error %v, want %v", err, tc.wantErr)
			}
			if err == nil {
				s.Free()
			}
		})
	}
}

func TestNewDKGStateWithRanks(t *testing.T) {
	tests := []struct {
		name    string
		partyID uint8
		ranks   []uint8
		thresh  int
		wantErr bool
	}{
		{"all zero ranks", 2, []uint8{0, 0, 0}, 2, false},
		{"empty ranks", 1, nil, 2, true},
		{"non-zero rank", 1, []uint8{0, 1, 0}, 2, true},
		{"party id out of range", 4, []uint8{0, 0, 0}, 2, true},
		{"threshold too high", 1, []uint8{0, 0}, 3, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewDKGStateWithRanks(tc.partyID, tc.ranks, tc.thresh)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got error %v, wantErr %v", err, tc.wantErr)
			}
			s.Free() // nil-safe
		})
	}
}

func TestDKGErrors(t *testing.T) {
	newParties := func(t *testing.T, n int) ([]*DKGState, []string) {
		t.Helper()
		states := make([]*DKGState, n)
		msgs := make([]string, n)
		for i := range states {
			s, err := NewDKGState(uint8(i+1), n, 2)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Free)
			states[i] = s
			if msgs[i], err = s.GenerateMsg1(); err != nil {
				t.Fatal(err)
			}
		}
		return states, msgs
	}

	t.Run("HandleMsg1 before GenerateMsg1", func(t *testing.T) {
		s, err := NewDKGState(1, 2, 2)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Free()
		_, err = s.HandleMsg1([]interface{}{"{}"})
		if !errors.Is(err, ErrFFICall) || !strings.Contains(err.Error(), "part1 not run") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("HandleMsg1 wrong message count", func(t *testing.T) {
		states, msgs := newParties(t, 3)
		if _, err := states[0].HandleMsg1([]interface{}{msgs[1]}); err == nil {
			t.Fatal("expected error for missing round 1 message")
		}
	})

	t.Run("HandleMsg1 own message", func(t *testing.T) {
		states, msgs := newParties(t, 2)
		if _, err := states[0].HandleMsg1([]interface{}{msgs[0]}); err == nil {
			t.Fatal("expected error for party's own round 1 message")
		}
	})

	t.Run("HandleMsg1 malformed JSON", func(t *testing.T) {
		states, _ := newParties(t, 2)
		if _, err := states[0].HandleMsg1([]interface{}{"{not json"}); err == nil {
			t.Fatal("expected error for malformed round 1 message")
		}
	})

	t.Run("HandleMsg1 unmarshalable input", func(t *testing.T) {
		states, _ := newParties(t, 2)
		_, err := states[0].HandleMsg1([]interface{}{make(chan int)})
		var jsonErr *json.UnsupportedTypeError
		if !errors.As(err, &jsonErr) {
			t.Fatalf("got %v, want json.UnsupportedTypeError", err)
		}
	})

	t.Run("HandleMsg2 wrong routing", func(t *testing.T) {
		states, msgs := newParties(t, 3)
		out := make([]string, 3)
		for i, s := range states {
			var err error
			if out[i], err = s.HandleMsg1(othersOf(msgs, i)); err != nil {
				t.Fatal(err)
			}
		}
		// Packets addressed to party 2 delivered to party 1.
		misrouted, err := Round2MessagesFor(2, out...)
		if err != nil {
			t.Fatal(err)
		}
		_, err = states[0].HandleMsg2(misrouted)
		if err == nil || !strings.Contains(err.Error(), "invalid route") {
			t.Fatalf("got %v, want invalid route error", err)
		}
	})

	t.Run("HandleMsg2 unrouted output", func(t *testing.T) {
		states, msgs := newParties(t, 2)
		out := make([]string, 2)
		for i, s := range states {
			var err error
			if out[i], err = s.HandleMsg1(othersOf(msgs, i)); err != nil {
				t.Fatal(err)
			}
		}
		// Passing the raw HandleMsg1 output instead of routed packets.
		if _, err := states[0].HandleMsg2([]interface{}{out[1]}); err == nil {
			t.Fatal("expected error for unrouted round 2 output")
		}
	})

	t.Run("HandleMsg2 before HandleMsg1", func(t *testing.T) {
		states, _ := newParties(t, 2)
		if _, err := states[0].HandleMsg2(nil); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("Finalize before completion", func(t *testing.T) {
		states, _ := newParties(t, 2)
		_, err := states[0].Finalize()
		if err == nil || !strings.Contains(err.Error(), "keyshare not ready") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestFreedState(t *testing.T) {
	d, err := NewDKGState(1, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	d.Free()
	d.Free() // idempotent

	keyshares := runDKG(t, 2, 2)
	s, err := NewSigningStateForMessage(keyshares[0], []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	s.Free()
	s.Free()

	var nilDKG *DKGState
	var nilSigning *SigningState
	calls := map[string]func() (string, error){
		"DKG GenerateMsg1":     d.GenerateMsg1,
		"DKG HandleMsg1":       func() (string, error) { return d.HandleMsg1(nil) },
		"DKG HandleMsg2":       func() (string, error) { return d.HandleMsg2(nil) },
		"DKG Finalize":         d.Finalize,
		"nil DKG GenerateMsg1": nilDKG.GenerateMsg1,
		"Signing GenerateMsg1": s.GenerateMsg1,
		"Signing HandleMsg1":   func() (string, error) { return s.HandleMsg1(nil) },
		"Signing GenerateMsg2": s.GenerateMsg2,
		"Signing HandleMsg2":   func() (string, error) { return s.HandleMsg2(nil) },
		"nil Signing Generate": nilSigning.GenerateMsg1,
	}
	for name, call := range calls {
		if _, err := call(); !errors.Is(err, ErrNilState) {
			t.Errorf("%s: got %v, want ErrNilState", name, err)
		}
	}
	nilDKG.Free()
	nilSigning.Free()
}

func TestSigningStateErrors(t *testing.T) {
	keyshares := runDKG(t, 2, 2)

	t.Run("empty message", func(t *testing.T) {
		if _, err := NewSigningStateForMessage(keyshares[0], nil); !errors.Is(err, ErrEmptyMessage) {
			t.Fatalf("got %v, want ErrEmptyMessage", err)
		}
	})
	t.Run("malformed keyshare", func(t *testing.T) {
		_, err := NewSigningState("{}", HashMessage("x"))
		if !errors.Is(err, ErrFFICall) || !strings.Contains(err.Error(), "parse keyshare") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestCombineSignaturesErrors(t *testing.T) {
	tests := []struct {
		name    string
		first   string
		others  []interface{}
		wantErr string
	}{
		{"malformed first partial", "{", nil, "parse first partial"},
		{"unmarshalable list", "{}", []interface{}{func() {}}, "marshal messages"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CombineSignatures(tc.first, tc.others)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}

	t.Run("missing or malformed share", func(t *testing.T) {
		keyshares := runDKG(t, 2, 2)
		msg := []byte("missing share")
		s1, _ := NewSigningStateForMessage(keyshares[0], msg)
		defer s1.Free()
		s2, _ := NewSigningStateForMessage(keyshares[1], msg)
		defer s2.Free()
		c1, _ := s1.GenerateMsg1()
		c2, _ := s2.GenerateMsg1()
		p1, err := s1.HandleMsg1([]interface{}{c2})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s2.HandleMsg1([]interface{}{c1}); err != nil {
			t.Fatal(err)
		}
		if _, err := CombineSignatures(p1, nil); err == nil {
			t.Fatal("aggregation succeeded with a missing signature share")
		}
		_, err = CombineSignatures(p1, []interface{}{"x"})
		if err == nil || !strings.Contains(err.Error(), "parse partial item") {
			t.Fatalf("malformed partial: got %v", err)
		}
	})
}

func TestVerifySignatureErrors(t *testing.T) {
	pub := strings.Repeat("00", 32)
	sig := strings.Repeat("00", 64)
	tests := []struct {
		name    string
		pub     string
		msg     []byte
		sig     string
		wantErr error
	}{
		{"empty message", pub, nil, sig, ErrEmptyMessage},
		{"non-hex public key", "zz", []byte("m"), sig, ErrFFICall},
		{"non-hex signature", pub, []byte("m"), "zz", ErrFFICall},
		{"bad public key JSON", `{"derived_public_key": 1}`, []byte("m"), sig, ErrFFICall},
		{"short signature", pub, []byte("m"), "00", ErrFFICall},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := VerifySignature(tc.pub, tc.msg, tc.sig)
			if ok || !errors.Is(err, tc.wantErr) {
				t.Fatalf("got (%v, %v), want (false, %v)", ok, err, tc.wantErr)
			}
		})
	}
}

func TestKeyDerivation(t *testing.T) {
	keyshares := runDKG(t, 2, 2)

	derived, err := DeriveKeyshare(keyshares[0], "m/0")
	if err != nil {
		t.Fatal(err)
	}
	if !groupPublicKey(t, derived).Equal(groupPublicKey(t, keyshares[0])) {
		t.Error("derived keyshare has a different group key")
	}

	for name, fn := range map[string]func(string, string) (string, error){
		"DerivePublicKey": DerivePublicKey,
		"DeriveKeyshare":  DeriveKeyshare,
	} {
		if _, err := fn("not json", "m"); !errors.Is(err, ErrFFICall) {
			t.Errorf("%s(malformed): got %v, want ErrFFICall", name, err)
		}
	}
}

func TestRound2MessagesFor(t *testing.T) {
	out1 := `[{"from":1,"to_id":1,"package":"a"},{"from":1,"to_id":2,"package":"b"}]`
	out2 := `[{"from":2,"to_id":0,"package":"c"},{"from":2,"to_id":2,"package":"d"}]`

	got, err := Round2MessagesFor(3, out1, out2)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(got)
	want := `[{"from":1,"to_id":2,"package":"b"},{"from":2,"to_id":2,"package":"d"}]`
	if string(encoded) != want {
		t.Errorf("got %s, want %s", encoded, want)
	}

	errCases := []struct {
		name    string
		partyID uint8
		outputs []string
	}{
		{"party id zero", 0, []string{out1}},
		{"not an array", 1, []string{`{"from":1}`}},
		{"packet not an object", 1, []string{`[1]`}},
		{"missing to_id", 1, []string{`[{"from":2}]`}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Round2MessagesFor(tc.partyID, tc.outputs...); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestCreatePartialSignatureIsPassthrough(t *testing.T) {
	got, err := CreatePartialSignature(`{"x":1}`, HashMessage("m"))
	if err != nil || got != `{"x":1}` {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestHashMessage(t *testing.T) {
	// SHA-256("abc") from FIPS 180-2.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	got := HashMessage("abc")
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("HashMessage(abc) = %x, want %s", got, want)
	}
}
