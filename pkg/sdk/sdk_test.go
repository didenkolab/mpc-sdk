package sdk

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// must returns a checker for (RawMsg, error) results.
func must(t *testing.T) func(RawMsg, error) RawMsg {
	return func(msg RawMsg, err error) RawMsg {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !json.Valid(msg) {
			t.Fatalf("invalid JSON payload %q", msg)
		}
		return msg
	}
}

func others(self int, msgs []RawMsg) []RawMsg {
	var out []RawMsg
	for i, m := range msgs {
		if i != self {
			out = append(out, m)
		}
	}
	return out
}

// route returns, for each recipient index, the point-to-point messages
// addressed to it. toID maps a recipient index to its wire "to_id".
func route(t *testing.T, outputs []RawMsg, toID func(int) uint8) [][]RawMsg {
	t.Helper()
	var all []RawMsg
	for _, out := range outputs {
		list, err := DecodeList(out)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, list...)
	}
	inboxes := make([][]RawMsg, len(outputs))
	for i := range outputs {
		inboxes[i] = FilterByToID(toID(i), all)
	}
	return inboxes
}

func derivedKey(t *testing.T, res string) string {
	t.Helper()
	var out struct {
		Key string `json:"derived_public_key"`
	}
	if err := json.Unmarshal([]byte(res), &out); err != nil || out.Key == "" {
		t.Fatalf("bad derive response %q: %v", res, err)
	}
	return out.Key
}

func dkls23Keygen(t *testing.T, n, threshold int) []RawMsg {
	t.Helper()
	parties := make([]*DKLS23DKG, n)
	for i := range parties {
		p, err := NewDKLS23DKG(uint8(i), n, threshold)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		parties[i] = p
	}
	byIndex := func(i int) uint8 { return uint8(i) }

	m1 := make([]RawMsg, n)
	for i, p := range parties {
		m1[i] = must(t)(p.Round1())
	}
	m2 := make([]RawMsg, n)
	for i, p := range parties {
		m2[i] = must(t)(p.Round2(others(i, m1)))
	}
	in2 := route(t, m2, byIndex)
	m3 := make([]RawMsg, n)
	for i, p := range parties {
		m3[i] = must(t)(p.Round3(in2[i]))
	}
	in3 := route(t, m3, byIndex)
	commitments := make([]string, n)
	for i, p := range parties {
		c, err := p.Commitment2()
		if err != nil {
			t.Fatal(err)
		}
		commitments[i] = c
	}
	m4 := make([]RawMsg, n)
	for i, p := range parties {
		m4[i] = must(t)(p.Round4(in3[i], commitments))
	}
	keyshares := make([]RawMsg, n)
	for i, p := range parties {
		keyshares[i] = must(t)(p.Finalize(others(i, m4)))
	}
	return keyshares
}

func dkls23Sign(t *testing.T, keyshares []RawMsg, ids []uint8, path string, hash [32]byte) string {
	t.Helper()
	n := len(keyshares)
	signers := make([]*DKLS23Signer, n)
	for i, ks := range keyshares {
		s, err := NewDKLS23Signer(ks, path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		signers[i] = s
	}
	toID := func(i int) uint8 { return ids[i] }

	s1 := make([]RawMsg, n)
	for i, s := range signers {
		s1[i] = must(t)(s.Round1())
	}
	s2 := make([]RawMsg, n)
	for i, s := range signers {
		s2[i] = must(t)(s.Round2(others(i, s1)))
	}
	in2 := route(t, s2, toID)
	s3 := make([]RawMsg, n)
	for i, s := range signers {
		s3[i] = must(t)(s.Round3(in2[i]))
	}
	in3 := route(t, s3, toID)
	partials := make([]*DKLS23Partial, n)
	for i, s := range signers {
		pre := must(t)(s.Presign(in3[i]))
		p, err := CreateDKLS23Partial(pre, hash)
		if err != nil {
			t.Fatal(err)
		}
		partials[i] = p
	}
	var msg4 []RawMsg
	for _, p := range partials[1:] {
		msg4 = append(msg4, p.Msg4)
	}
	sig, err := CombineDKLS23(partials[0].Partial, msg4)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func verifySecp256k1(t *testing.T, pubHex, sigHex string, hash [32]byte) {
	t.Helper()
	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := secp.ParsePubKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != 64 {
		t.Fatalf("bad signature %q", sigHex)
	}
	var r, s secp.ModNScalar
	r.SetByteSlice(sig[:32])
	s.SetByteSlice(sig[32:])
	if !secpecdsa.NewSignature(&r, &s).Verify(hash[:], pub) {
		t.Fatal("signature rejected by decred secp256k1")
	}
}

func TestDKLS23EndToEnd(t *testing.T) {
	tests := []struct {
		n, threshold int
		signers      []int
		path         string
	}{
		{2, 2, []int{0, 1}, "m"},
		{3, 2, []int{0, 2}, "m"},
		{3, 2, []int{2, 1}, "m/44/60/0/0/0"},
		{3, 3, []int{0, 1, 2}, "m/0/1"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d-of-%d signers %v path %s", tc.threshold, tc.n, tc.signers, tc.path), func(t *testing.T) {
			keyshares := dkls23Keygen(t, tc.n, tc.threshold)

			var pub string
			for i, ks := range keyshares {
				res, err := DeriveDKLS23Public(ks, tc.path)
				if err != nil {
					t.Fatal(err)
				}
				key := derivedKey(t, res)
				if i == 0 {
					pub = key
				} else if key != pub {
					t.Fatalf("party %d derived %s, want %s", i, key, pub)
				}
			}

			selected := make([]RawMsg, len(tc.signers))
			ids := make([]uint8, len(tc.signers))
			for i, idx := range tc.signers {
				selected[i] = keyshares[idx]
				ids[i] = uint8(idx)
			}
			hash := sha256.Sum256([]byte(t.Name()))
			sig := dkls23Sign(t, selected, ids, tc.path, hash)
			verifySecp256k1(t, pub, sig, hash)
		})
	}
}

func frostKeygen(t *testing.T, n, threshold int) []RawMsg {
	t.Helper()
	parties := make([]*FrostDKG, n)
	for i := range parties {
		p, err := NewFrostDKG(uint8(i+1), n, threshold)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		parties[i] = p
	}
	m1 := make([]RawMsg, n)
	for i, p := range parties {
		m1[i] = must(t)(p.Round1())
	}
	m2 := make([]RawMsg, n)
	for i, p := range parties {
		m2[i] = must(t)(p.Round2(others(i, m1)))
	}
	// FROST packet to_id values are 0-based.
	in2 := route(t, m2, func(i int) uint8 { return uint8(i) })
	keyshares := make([]RawMsg, n)
	for i, p := range parties {
		ks := must(t)(p.Round3(in2[i]))
		final := must(t)(p.Finalize())
		if string(final) != string(ks) {
			t.Fatalf("party %d: Finalize differs from Round3", i+1)
		}
		keyshares[i] = ks
	}
	return keyshares
}

func TestFROSTEndToEnd(t *testing.T) {
	tests := []struct {
		n, threshold int
		signers      []int
	}{
		{2, 2, []int{0, 1}},
		{3, 2, []int{2, 0}},
		{3, 3, []int{0, 1, 2}},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d-of-%d signers %v", tc.threshold, tc.n, tc.signers), func(t *testing.T) {
			keyshares := frostKeygen(t, tc.n, tc.threshold)
			res, err := DeriveFrostPublic(keyshares[0], "m")
			if err != nil {
				t.Fatal(err)
			}
			pub, err := hex.DecodeString(derivedKey(t, res))
			if err != nil || len(pub) != ed25519.PublicKeySize {
				t.Fatalf("bad public key: %v", err)
			}

			hash := sha256.Sum256([]byte(t.Name()))
			signers := make([]*FrostSigner, len(tc.signers))
			for i, idx := range tc.signers {
				s, err := NewFrostSigner(keyshares[idx], hash)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(s.Close)
				signers[i] = s
			}
			commitments := make([]RawMsg, len(signers))
			for i, s := range signers {
				commitments[i] = must(t)(s.Round1())
			}
			shares := make([]RawMsg, len(signers))
			for i, s := range signers {
				shares[i] = must(t)(s.Round2(others(i, commitments)))
				// Rounds 3 and 4 are no-ops kept for API symmetry.
				must(t)(s.Round3())
				must(t)(s.Round4(nil))
			}

			sigHex, err := CombineFrost(shares[0], others(0, shares))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := hex.DecodeString(sigHex)
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(pub, hash[:], sig) {
				t.Fatal("signature rejected by crypto/ed25519")
			}

			// The DKLs23-style flow through CreateFrostPartial is equivalent.
			partials := make([]*FrostPartial, len(shares))
			for i, sh := range shares {
				if partials[i], err = CreateFrostPartial(sh, hash); err != nil {
					t.Fatal(err)
				}
			}
			var msg2 []RawMsg
			for _, p := range partials[1:] {
				msg2 = append(msg2, p.Msg2)
			}
			sigHex2, err := CombineFrost(partials[0].Partial, msg2)
			if err != nil {
				t.Fatal(err)
			}
			if sig2, _ := hex.DecodeString(sigHex2); !ed25519.Verify(pub, hash[:], sig2) {
				t.Fatal("signature from CreateFrostPartial flow rejected")
			}
		})
	}
}

func TestDecodeList(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{`[{"a":1},{"b":2}]`, 2, false},
		{`[]`, 0, false},
		{`{"a":1}`, 1, false},
		{`"str"`, 1, false},
		{`not json`, 1, false},
		{``, 0, true},
	}
	for _, tc := range tests {
		got, err := DecodeList(RawMsg(tc.in))
		if (err != nil) != tc.wantErr || len(got) != tc.want {
			t.Errorf("DecodeList(%q) = %d items, %v", tc.in, len(got), err)
		}
	}
}

func TestFilterByToID(t *testing.T) {
	msgs := []RawMsg{
		RawMsg(`{"to_id":0,"x":1}`),
		RawMsg(`{"to_id":1,"x":2}`),
		RawMsg(`{"to_id":1,"x":3}`),
		RawMsg(`{"x":4}`),
		RawMsg(`{"to_id":257}`),
		RawMsg(`garbage`),
	}
	if got := FilterByToID(1, msgs); len(got) != 2 || string(got[0]) != `{"to_id":1,"x":2}` {
		t.Fatalf("to_id 1: %q", got)
	}
	if got := FilterByToID(0, msgs); len(got) != 1 {
		t.Fatalf("to_id 0: %q", got)
	}
	if got := FilterByToID(2, msgs); len(got) != 0 {
		t.Fatalf("to_id 2: %q", got)
	}
}

func TestErrors(t *testing.T) {
	hash := sha256.Sum256([]byte("x"))
	tests := []struct {
		name string
		call func() error
	}{
		{"DKLs23 DKG invalid party", func() error { _, err := NewDKLS23DKG(3, 2, 2); return err }},
		{"DKLs23 DKG invalid threshold", func() error { _, err := NewDKLS23DKG(0, 2, 3); return err }},
		{"DKLs23 signer malformed keyshare", func() error { _, err := NewDKLS23Signer(RawMsg(`{}`), "m"); return err }},
		{"DKLs23 partial unknown presignature", func() error {
			_, err := CreateDKLS23Partial(RawMsg(`{"presignature_handle":"00"}`), hash)
			return err
		}},
		{"DKLs23 combine malformed partial", func() error { _, err := CombineDKLS23(RawMsg(`{}`), nil); return err }},
		{"DKLs23 derive malformed keyshare", func() error { _, err := DeriveDKLS23Public(RawMsg(`{}`), "m"); return err }},
		{"DKLs23 round with garbage", func() error {
			p, err := NewDKLS23DKG(0, 2, 2)
			if err != nil {
				return nil
			}
			defer p.Close()
			_, err = p.Round2([]RawMsg{RawMsg(`not json`)})
			return err
		}},
		{"FROST DKG zero party ID", func() error { _, err := NewFrostDKG(0, 2, 2); return err }},
		{"FROST signer malformed keyshare", func() error { _, err := NewFrostSigner(RawMsg(`{}`), hash); return err }},
		{"FROST combine malformed share", func() error { _, err := CombineFrost(RawMsg(`{}`), nil); return err }},
		{"FROST derive malformed keyshare", func() error { _, err := DeriveFrostPublic(RawMsg(`{}`), "m"); return err }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	// Close is safe on zero values.
	(&DKLS23DKG{}).Close()
	(&DKLS23Signer{}).Close()
	(&FrostDKG{}).Close()
	(&FrostSigner{}).Close()
}

func TestToRaw(t *testing.T) {
	if _, err := toRaw("not json"); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if raw, err := toRaw(`{"a":1}`); err != nil || string(raw) != `{"a":1}` {
		t.Fatalf("toRaw = %q, %v", raw, err)
	}
	if got := parseList([]RawMsg{RawMsg(`{"a":1}`), RawMsg(`plain`)}); got[1] != "plain" {
		t.Fatalf("parseList = %#v", got)
	}
}
