package dkls23

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// p2pMessage is the routing header carried by point-to-point protocol messages.
type p2pMessage struct {
	FromID uint8 `json:"from_id"`
	ToID   uint8 `json:"to_id"`
}

func decodeObject(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return v
}

// routeP2P splits each party's output array into per-recipient inboxes keyed
// by the recipient's index in ids.
func routeP2P(t *testing.T, ids []uint8, outputs []string) [][]any {
	t.Helper()
	index := make(map[uint8]int, len(ids))
	for i, id := range ids {
		index[id] = i
	}
	inboxes := make([][]any, len(ids))
	for sender, out := range outputs {
		var arr []json.RawMessage
		if err := json.Unmarshal([]byte(out), &arr); err != nil {
			t.Fatalf("decode p2p array: %v", err)
		}
		for _, raw := range arr {
			var hdr p2pMessage
			if err := json.Unmarshal(raw, &hdr); err != nil {
				t.Fatalf("decode p2p header: %v", err)
			}
			if hdr.FromID != ids[sender] {
				t.Fatalf("message from party %d claims from_id %d", ids[sender], hdr.FromID)
			}
			to, ok := index[hdr.ToID]
			if !ok {
				t.Fatalf("message addressed to unknown party %d", hdr.ToID)
			}
			inboxes[to] = append(inboxes[to], decodeObject(t, string(raw)))
		}
	}
	return inboxes
}

// othersOf returns the broadcast messages of every party except self.
func othersOf(t *testing.T, self int, msgs []string) []any {
	t.Helper()
	var out []any
	for i, m := range msgs {
		if i != self {
			out = append(out, decodeObject(t, m))
		}
	}
	return out
}

// runDKG executes a full in-process DKG. If ranks is nil a standard t-of-n key
// is generated; otherwise a ranked key with len(ranks) parties.
func runDKG(t *testing.T, n, threshold int, ranks []uint8) []string {
	t.Helper()
	ids := make([]uint8, n)
	states := make([]*DKGState, n)
	for i := range n {
		ids[i] = uint8(i)
		var (
			st  *DKGState
			err error
		)
		if ranks == nil {
			st, err = NewDKGState(uint8(i), n, threshold)
		} else {
			st, err = NewDKGStateWithRanks(uint8(i), ranks, threshold)
		}
		if err != nil {
			t.Fatalf("party %d: new DKG state: %v", i, err)
		}
		t.Cleanup(st.Free)
		states[i] = st
	}

	msg1 := make([]string, n)
	for i, st := range states {
		var err error
		if msg1[i], err = st.GenerateMsg1(); err != nil {
			t.Fatalf("party %d: msg1: %v", i, err)
		}
	}

	msg2 := make([]string, n)
	for i, st := range states {
		var err error
		if msg2[i], err = st.HandleMsg1(othersOf(t, i, msg1)); err != nil {
			t.Fatalf("party %d: handle msg1: %v", i, err)
		}
	}
	in2 := routeP2P(t, ids, msg2)

	msg3 := make([]string, n)
	for i, st := range states {
		var err error
		if msg3[i], err = st.HandleMsg2(in2[i]); err != nil {
			t.Fatalf("party %d: handle msg2: %v", i, err)
		}
	}
	in3 := routeP2P(t, ids, msg3)

	commitments := make([]string, n)
	for i, st := range states {
		var err error
		if commitments[i], err = st.CalculateCommitment2(); err != nil {
			t.Fatalf("party %d: commitment2: %v", i, err)
		}
	}

	msg4 := make([]string, n)
	for i, st := range states {
		var err error
		if msg4[i], err = st.HandleMsg3(in3[i], commitments); err != nil {
			t.Fatalf("party %d: handle msg3: %v", i, err)
		}
	}

	keyshares := make([]string, n)
	for i, st := range states {
		var err error
		if keyshares[i], err = st.HandleMsg4(othersOf(t, i, msg4)); err != nil {
			t.Fatalf("party %d: handle msg4: %v", i, err)
		}
	}
	return keyshares
}

func keysharePartyID(t *testing.T, keyshare string) uint8 {
	t.Helper()
	var ks struct {
		PartyID uint8 `json:"party_id"`
	}
	if err := json.Unmarshal([]byte(keyshare), &ks); err != nil {
		t.Fatalf("decode keyshare: %v", err)
	}
	return ks.PartyID
}

func keysharePublicKey(t *testing.T, keyshare string) string {
	t.Helper()
	var ks struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal([]byte(keyshare), &ks); err != nil {
		t.Fatalf("decode keyshare: %v", err)
	}
	if ks.PublicKey == "" {
		t.Fatal("keyshare has no public_key")
	}
	return ks.PublicKey
}

// runDSG signs hash with the given keyshares and returns the hex signature
// produced by the first signer.
func runDSG(t *testing.T, keyshares []string, path string, hash [32]byte) string {
	t.Helper()
	n := len(keyshares)
	ids := make([]uint8, n)
	states := make([]*DSGState, n)
	for i, ks := range keyshares {
		ids[i] = keysharePartyID(t, ks)
		st, err := NewDSGState(ks, path)
		if err != nil {
			t.Fatalf("signer %d: new DSG state: %v", i, err)
		}
		t.Cleanup(st.Free)
		states[i] = st
	}

	msg1 := make([]string, n)
	for i, st := range states {
		var err error
		if msg1[i], err = st.GenerateMsg1(); err != nil {
			t.Fatalf("signer %d: msg1: %v", i, err)
		}
	}
	msg2 := make([]string, n)
	for i, st := range states {
		var err error
		if msg2[i], err = st.HandleMsg1(othersOf(t, i, msg1)); err != nil {
			t.Fatalf("signer %d: handle msg1: %v", i, err)
		}
	}
	in2 := routeP2P(t, ids, msg2)
	msg3 := make([]string, n)
	for i, st := range states {
		var err error
		if msg3[i], err = st.HandleMsg2(in2[i]); err != nil {
			t.Fatalf("signer %d: handle msg2: %v", i, err)
		}
	}
	in3 := routeP2P(t, ids, msg3)

	partials := make([]struct {
		Partial json.RawMessage `json:"partial"`
		Msg4    json.RawMessage `json:"msg4"`
	}, n)
	for i, st := range states {
		presig, err := st.HandleMsg3(in3[i])
		if err != nil {
			t.Fatalf("signer %d: handle msg3: %v", i, err)
		}
		res, err := CreatePartialSignature(presig, hash)
		if err != nil {
			t.Fatalf("signer %d: partial signature: %v", i, err)
		}
		if err := json.Unmarshal([]byte(res), &partials[i]); err != nil {
			t.Fatalf("signer %d: decode partial: %v", i, err)
		}
	}

	var otherMsg4 []any
	for _, p := range partials[1:] {
		otherMsg4 = append(otherMsg4, decodeObject(t, string(p.Msg4)))
	}
	sig, err := CombineSignatures(string(partials[0].Partial), otherMsg4)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	return sig
}

// verifyECDSA checks a hex r||s signature against a hex public key using the
// independent decred secp256k1 implementation.
func verifyECDSA(t *testing.T, pubHex, sigHex string, hash [32]byte) {
	t.Helper()
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	pub, err := secp.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != 64 {
		t.Fatalf("signature must be 64 hex-encoded bytes, got %q (%v)", sigHex, err)
	}
	var r, s secp.ModNScalar
	if r.SetByteSlice(sigBytes[:32]) || s.SetByteSlice(sigBytes[32:]) {
		t.Fatal("signature scalar overflows the curve order")
	}
	if s.IsOverHalfOrder() {
		t.Error("signature s is not low-S normalized")
	}
	if !secpecdsa.NewSignature(&r, &s).Verify(hash[:], pub) {
		t.Fatal("signature does not verify against the group public key")
	}
}

func TestDKGAndSigning(t *testing.T) {
	tests := []struct {
		name      string
		n         int
		threshold int
		ranks     []uint8
		signers   []int
	}{
		{name: "2-of-2", n: 2, threshold: 2, signers: []int{0, 1}},
		{name: "2-of-3 signers 0,1", n: 3, threshold: 2, signers: []int{0, 1}},
		{name: "2-of-3 signers 1,2", n: 3, threshold: 2, signers: []int{1, 2}},
		{name: "2-of-3 signers 2,0", n: 3, threshold: 2, signers: []int{2, 0}},
		{name: "3-of-3", n: 3, threshold: 3, signers: []int{0, 1, 2}},
		{name: "3-of-5 signers 0,2,4", n: 5, threshold: 3, signers: []int{0, 2, 4}},
		{name: "ranked 2-of-3 with rank-0 signer", n: 3, threshold: 2, ranks: []uint8{0, 1, 1}, signers: []int{0, 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyshares := runDKG(t, tc.n, tc.threshold, tc.ranks)

			pub := keysharePublicKey(t, keyshares[0])
			for i, ks := range keyshares {
				if got := keysharePublicKey(t, ks); got != pub {
					t.Fatalf("party %d public key %s, want %s", i, got, pub)
				}
				if got := keysharePartyID(t, ks); got != uint8(i) {
					t.Fatalf("party %d keyshare has party_id %d", i, got)
				}
			}

			selected := make([]string, len(tc.signers))
			for i, idx := range tc.signers {
				selected[i] = keyshares[idx]
			}
			hash := sha256.Sum256([]byte("dkls23 " + tc.name))
			sig := runDSG(t, selected, "m", hash)
			verifyECDSA(t, pub, sig, hash)
		})
	}
}

func TestChildKeyDerivation(t *testing.T) {
	keyshares := runDKG(t, 3, 2, nil)
	rootPub := keysharePublicKey(t, keyshares[0])

	root, err := DeriveChildPublicKey(keyshares[0], "m")
	if err != nil {
		t.Fatalf("derive root: %v", err)
	}
	if !strings.EqualFold(root, rootPub) {
		t.Fatalf("path m derived %s, want root key %s", root, rootPub)
	}

	paths := []string{"m/0", "m/0/1", "m/44/60/0/0/7"}
	seen := map[string]bool{strings.ToLower(rootPub): true}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			var childPub string
			for i, ks := range keyshares {
				got, err := DeriveChildPublicKey(ks, path)
				if err != nil {
					t.Fatalf("party %d derive: %v", i, err)
				}
				if i == 0 {
					childPub = got
				} else if got != childPub {
					t.Fatalf("party %d derived %s, want %s", i, got, childPub)
				}
			}
			if seen[childPub] {
				t.Fatalf("derived key %s is not unique", childPub)
			}
			seen[childPub] = true

			// Signing from the root keyshare at the child path.
			hash := sha256.Sum256([]byte("child via path " + path))
			sig := runDSG(t, []string{keyshares[0], keyshares[2]}, path, hash)
			verifyECDSA(t, childPub, sig, hash)

			// Signing with explicitly derived child keyshares at "m".
			var derived []string
			for _, idx := range []int{1, 2} {
				ks, err := DeriveKeyshare(keyshares[idx], path)
				if err != nil {
					t.Fatalf("derive keyshare %d: %v", idx, err)
				}
				if got := keysharePublicKey(t, ks); !strings.EqualFold(got, childPub) {
					t.Fatalf("derived keyshare public key %s, want %s", got, childPub)
				}
				derived = append(derived, ks)
			}
			hash = sha256.Sum256([]byte("child via keyshare " + path))
			sig = runDSG(t, derived, "m", hash)
			verifyECDSA(t, childPub, sig, hash)
		})
	}
}

func TestNewDKGStateValidation(t *testing.T) {
	tests := []struct {
		name      string
		partyID   uint8
		n         int
		threshold int
		want      error
	}{
		{"party out of range", 5, 2, 2, ErrInvalidPartyID},
		{"party equals n", 2, 2, 2, ErrInvalidPartyID},
		{"single party", 0, 1, 1, ErrInvalidPartyID},
		{"too many parties", 0, 257, 2, ErrInvalidPartyID},
		{"threshold above n", 0, 2, 5, ErrInvalidThreshold},
		{"threshold one", 0, 2, 1, ErrInvalidThreshold},
		{"threshold zero", 0, 3, 0, ErrInvalidThreshold},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, err := NewDKGState(tc.partyID, tc.n, tc.threshold)
			if !errors.Is(err, tc.want) {
				st.Free()
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewDKGStateWithRanksValidation(t *testing.T) {
	tests := []struct {
		name      string
		partyID   uint8
		ranks     []uint8
		threshold int
		want      error
	}{
		{"empty ranks", 0, nil, 2, ErrInvalidRanks},
		{"single rank", 0, []uint8{0}, 2, ErrInvalidRanks},
		{"party out of range", 3, []uint8{0, 1, 1}, 2, ErrInvalidPartyID},
		{"threshold one", 0, []uint8{0, 0}, 1, ErrInvalidThreshold},
		{"threshold above n", 0, []uint8{0, 1}, 3, ErrInvalidThreshold},
		{"rank equals threshold", 0, []uint8{0, 2, 1}, 2, ErrInvalidRanks},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, err := NewDKGStateWithRanks(tc.partyID, tc.ranks, tc.threshold)
			if !errors.Is(err, tc.want) {
				st.Free()
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestFreedStateReturnsErrNilState(t *testing.T) {
	dkg, err := NewDKGState(0, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	dkg.Free()
	dkg.Free() // idempotent

	dkgCalls := map[string]func() error{
		"GenerateMsg1":         func() error { _, err := dkg.GenerateMsg1(); return err },
		"HandleMsg1":           func() error { _, err := dkg.HandleMsg1(nil); return err },
		"HandleMsg2":           func() error { _, err := dkg.HandleMsg2(nil); return err },
		"CalculateCommitment2": func() error { _, err := dkg.CalculateCommitment2(); return err },
		"HandleMsg3":           func() error { _, err := dkg.HandleMsg3(nil, nil); return err },
		"HandleMsg4":           func() error { _, err := dkg.HandleMsg4(nil); return err },
	}
	var dsg *DSGState
	dsgCalls := map[string]func() error{
		"DSG.GenerateMsg1": func() error { _, err := dsg.GenerateMsg1(); return err },
		"DSG.HandleMsg1":   func() error { _, err := dsg.HandleMsg1(nil); return err },
		"DSG.HandleMsg2":   func() error { _, err := dsg.HandleMsg2(nil); return err },
		"DSG.HandleMsg3":   func() error { _, err := dsg.HandleMsg3(nil); return err },
	}
	for _, calls := range []map[string]func() error{dkgCalls, dsgCalls} {
		for name, call := range calls {
			if err := call(); !errors.Is(err, ErrNilState) {
				t.Errorf("%s: got %v, want ErrNilState", name, err)
			}
		}
	}
	dsg.Free() // nil receiver is a no-op
}

func TestFFIErrorsAreReported(t *testing.T) {
	keyshares := runDKG(t, 2, 2, nil)
	hash := sha256.Sum256([]byte("errors"))

	tests := []struct {
		name string
		call func() error
	}{
		{"DSG with malformed keyshare", func() error {
			_, err := NewDSGState("{not json", "m")
			return err
		}},
		{"DSG with malformed path", func() error {
			_, err := NewDSGState(keyshares[0], "not/a/path")
			return err
		}},
		{"derive public key with malformed path", func() error {
			_, err := DerivePublicKey(keyshares[0], "x/1")
			return err
		}},
		{"derive child public key with malformed keyshare", func() error {
			_, err := DeriveChildPublicKey("{}", "m")
			return err
		}},
		{"derive keyshare with malformed keyshare", func() error {
			_, err := DeriveKeyshare("[]", "m/1")
			return err
		}},
		{"partial signature with unknown presignature", func() error {
			_, err := CreatePartialSignature(`{"presignature_handle":"00"}`, hash)
			return err
		}},
		{"combine with malformed partial", func() error {
			_, err := CombineSignatures("{}", nil)
			return err
		}},
		{"DKG handle msg1 with garbage", func() error {
			st, err := NewDKGState(0, 2, 2)
			if err != nil {
				return nil
			}
			defer st.Free()
			_, err = st.HandleMsg1([]any{"garbage"})
			return err
		}},
		{"DKG handle msg1 with missing messages", func() error {
			st, err := NewDKGState(0, 3, 2)
			if err != nil {
				return nil
			}
			defer st.Free()
			if _, err := st.GenerateMsg1(); err != nil {
				return nil
			}
			_, err = st.HandleMsg1([]any{})
			return err
		}},
		{"unmarshalable Go input", func() error {
			st, err := NewDKGState(0, 2, 2)
			if err != nil {
				return nil
			}
			defer st.Free()
			_, err = st.HandleMsg1([]any{make(chan int)})
			return err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestPresignatureIsSingleUse(t *testing.T) {
	keyshares := runDKG(t, 2, 2, nil)
	states := make([]*DSGState, 2)
	for i, ks := range keyshares {
		st, err := NewDSGState(ks, "m")
		if err != nil {
			t.Fatal(err)
		}
		defer st.Free()
		states[i] = st
	}
	m1 := make([]string, 2)
	for i, st := range states {
		var err error
		if m1[i], err = st.GenerateMsg1(); err != nil {
			t.Fatal(err)
		}
	}
	m2 := make([]string, 2)
	for i, st := range states {
		var err error
		if m2[i], err = st.HandleMsg1(othersOf(t, i, m1)); err != nil {
			t.Fatal(err)
		}
	}
	in2 := routeP2P(t, []uint8{0, 1}, m2)
	m3 := make([]string, 2)
	for i, st := range states {
		var err error
		if m3[i], err = st.HandleMsg2(in2[i]); err != nil {
			t.Fatal(err)
		}
	}
	in3 := routeP2P(t, []uint8{0, 1}, m3)
	presig, err := states[0].HandleMsg3(in3[0])
	if err != nil {
		t.Fatal(err)
	}

	hash := sha256.Sum256([]byte("once"))
	if _, err := CreatePartialSignature(presig, hash); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := CreatePartialSignature(presig, hash); err == nil {
		t.Fatal("reusing a presignature must fail")
	}
}

func ExampleNewDKGState() {
	st, err := NewDKGState(0, 3, 2)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer st.Free()
	_, err = NewDKGState(3, 3, 2)
	fmt.Println(err)
	// Output: dkls23: invalid party ID or party count
}
