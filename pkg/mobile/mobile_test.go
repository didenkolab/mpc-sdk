package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Public key of secp256k1 private key 1 (the generator point).
const generatorPub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

// jsonArray encodes raw JSON values as a JSON array string.
func jsonArray(t *testing.T, items []json.RawMessage) string {
	t.Helper()
	if items == nil {
		items = []json.RawMessage{}
	}
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func othersArray(t *testing.T, self int, msgs []string) string {
	t.Helper()
	var out []json.RawMessage
	for i, m := range msgs {
		if i != self {
			out = append(out, json.RawMessage(m))
		}
	}
	return jsonArray(t, out)
}

// routeArrays splits P2P output arrays into JSON-array inboxes; ids maps an
// output index to the party ID used in "to_id".
func routeArrays(t *testing.T, ids []int, outputs []string) []string {
	t.Helper()
	index := map[int]int{}
	for i, id := range ids {
		index[id] = i
	}
	inbox := make([][]json.RawMessage, len(outputs))
	for _, out := range outputs {
		var items []json.RawMessage
		if err := json.Unmarshal([]byte(out), &items); err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			var hdr struct {
				ToID int `json:"to_id"`
			}
			if err := json.Unmarshal(item, &hdr); err != nil {
				t.Fatal(err)
			}
			inbox[index[hdr.ToID]] = append(inbox[index[hdr.ToID]], item)
		}
	}
	res := make([]string, len(outputs))
	for i := range res {
		res[i] = jsonArray(t, inbox[i])
	}
	return res
}

func ok(t *testing.T) func(string, error) string {
	return func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
}

func keygen(t *testing.T, n, threshold int) []string {
	t.Helper()
	states := make([]*DKLS23DKGState, n)
	ids := make([]int, n)
	for i := range states {
		st, err := NewDKLS23DKGState(i, n, threshold)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.Free)
		states[i] = st
		ids[i] = i
	}
	m1 := make([]string, n)
	for i, st := range states {
		m1[i] = ok(t)(st.GenerateMsg1())
	}
	m2 := make([]string, n)
	for i, st := range states {
		m2[i] = ok(t)(st.HandleMsg1(othersArray(t, i, m1)))
	}
	in2 := routeArrays(t, ids, m2)
	m3 := make([]string, n)
	for i, st := range states {
		m3[i] = ok(t)(st.HandleMsg2(in2[i]))
	}
	in3 := routeArrays(t, ids, m3)
	commitments := make([]string, n)
	for i, st := range states {
		commitments[i] = ok(t)(st.CalculateCommitment2())
	}
	commitJSON, err := json.Marshal(commitments)
	if err != nil {
		t.Fatal(err)
	}
	m4 := make([]string, n)
	for i, st := range states {
		m4[i] = ok(t)(st.HandleMsg3(in3[i], string(commitJSON)))
	}
	keyshares := make([]string, n)
	for i, st := range states {
		keyshares[i] = ok(t)(st.HandleMsg4(othersArray(t, i, m4)))
	}
	return keyshares
}

func sign(t *testing.T, keyshares []string, ids []int, path, hashHex string) string {
	t.Helper()
	n := len(keyshares)
	states := make([]*DKLS23DSGState, n)
	for i, ks := range keyshares {
		st, err := NewDKLS23DSGState(ks, path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.Free)
		states[i] = st
	}
	m1 := make([]string, n)
	for i, st := range states {
		m1[i] = ok(t)(st.GenerateMsg1())
	}
	m2 := make([]string, n)
	for i, st := range states {
		m2[i] = ok(t)(st.HandleMsg1(othersArray(t, i, m1)))
	}
	in2 := routeArrays(t, ids, m2)
	m3 := make([]string, n)
	for i, st := range states {
		m3[i] = ok(t)(st.HandleMsg2(in2[i]))
	}
	in3 := routeArrays(t, ids, m3)

	var partial0 json.RawMessage
	var msg4 []json.RawMessage
	for i, st := range states {
		presig := ok(t)(st.HandleMsg3(in3[i]))
		res := ok(t)(DKLS23CreatePartialSignature(presig, hashHex))
		var p struct {
			Partial json.RawMessage `json:"partial"`
			Msg4    json.RawMessage `json:"msg4"`
		}
		if err := json.Unmarshal([]byte(res), &p); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			partial0 = p.Partial
		} else {
			msg4 = append(msg4, p.Msg4)
		}
	}
	return ok(t)(DKLS23CombineSignatures(string(partial0), jsonArray(t, msg4)))
}

func derivedKey(t *testing.T, res string) string {
	t.Helper()
	var out struct {
		Key string `json:"derived_public_key"`
	}
	if err := json.Unmarshal([]byte(res), &out); err != nil || out.Key == "" {
		t.Fatalf("bad derive response %q", res)
	}
	return out.Key
}

func verify(t *testing.T, pubHex, sigHex string, hash [32]byte) {
	t.Helper()
	pubBytes, _ := hex.DecodeString(pubHex)
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

func TestKeygenAndSigning(t *testing.T) {
	tests := []struct {
		n, threshold int
		signers      []int
		path         string
		hashPrefix   string
	}{
		{2, 2, []int{0, 1}, "m", ""},
		{3, 2, []int{2, 0}, "m/44/195/0/0/0", "0x"},
		{3, 3, []int{0, 1, 2}, "m/1", "0X"},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%d-of-%d %s", tc.threshold, tc.n, tc.path), func(t *testing.T) {
			keyshares := keygen(t, tc.n, tc.threshold)
			pub := derivedKey(t, ok(t)(DKLS23DerivePublicKey(keyshares[0], tc.path)))

			selected := make([]string, len(tc.signers))
			for i, idx := range tc.signers {
				selected[i] = keyshares[idx]
			}
			hash := sha256.Sum256([]byte(t.Name()))
			sig := sign(t, selected, tc.signers, tc.path, tc.hashPrefix+hex.EncodeToString(hash[:]))
			verify(t, pub, sig, hash)

			// A derived keyshare signs for the same child key at "m".
			derived := make([]string, len(selected))
			for i, ks := range selected {
				derived[i] = ok(t)(DKLS23DeriveKeyshare(ks, tc.path))
			}
			hash = sha256.Sum256([]byte("derived " + t.Name()))
			sig = sign(t, derived, tc.signers, "m", hex.EncodeToString(hash[:]))
			verify(t, pub, sig, hash)

			// Addresses derived from the MPC key are well formed.
			if addr := ok(t)(PublicKeyToTronAddress(pub)); !strings.HasPrefix(addr, "T") || len(addr) != 34 {
				t.Fatalf("Tron address %q", addr)
			}
			if addr := ok(t)(PublicKeyToEthereumAddress(pub)); len(addr) != 42 {
				t.Fatalf("Ethereum address %q", addr)
			}
		})
	}
}

func TestAddresses(t *testing.T) {
	tests := []struct {
		name string
		got  func() (string, error)
		want string
	}{
		{"ethereum", func() (string, error) { return PublicKeyToEthereumAddress(generatorPub) }, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"},
		{"bitcoin", func() (string, error) { return PublicKeyToBitcoinAddress(generatorPub, true) }, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"},
		{"bitcoin testnet", func() (string, error) { return PublicKeyToBitcoinAddress(generatorPub, false) }, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"},
		{"segwit", func() (string, error) { return PublicKeyToBitcoinSegWitAddress(generatorPub, true) }, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{"tron", func() (string, error) { return PublicKeyToTronAddress(generatorPub) }, "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"},
		{"tron with 0x prefix", func() (string, error) { return PublicKeyToTronAddress("0x" + generatorPub) }, "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.got()
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestBuildTronTransaction(t *testing.T) {
	from := ok(t)(PublicKeyToTronAddress(generatorPub))
	keyshares := keygen(t, 2, 2)
	to := ok(t)(PublicKeyToTronAddress(derivedKey(t, ok(t)(DKLS23DerivePublicKey(keyshares[0], "m")))))

	res := ok(t)(BuildTronTransaction(from, to, 1_000_000))
	var tx TronRawTxResult
	if err := json.Unmarshal([]byte(res), &tx); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(tx.RawDataHex)
	if err != nil || len(raw) == 0 {
		t.Fatalf("raw data %q", tx.RawDataHex)
	}
	sum := sha256.Sum256(raw)
	if tx.TxID != hex.EncodeToString(sum[:]) || tx.MessageHash != tx.TxID {
		t.Fatalf("tx id %s / hash %s do not match SHA-256 of raw data", tx.TxID, tx.MessageHash)
	}

	// Deterministic with explicit reference block and timestamps.
	a := ok(t)(BuildTronTransactionWithRefBlock(from, to, 5, "0d3a", "8fa9e75800000000", 2000, 1000))
	b := ok(t)(BuildTronTransactionWithRefBlock(from, to, 5, "0d3a", "8fa9e75800000000", 2000, 1000))
	if a != b {
		t.Fatal("transaction building is not deterministic")
	}

	errCases := map[string]func() (string, error){
		"zero amount":     func() (string, error) { return BuildTronTransaction(from, to, 0) },
		"negative amount": func() (string, error) { return BuildTronTransaction(from, to, -1) },
		"bad from":        func() (string, error) { return BuildTronTransaction("nope", to, 1) },
		"expired": func() (string, error) {
			return BuildTronTransactionWithRefBlock(from, to, 1, "0d3a", "8fa9e75800000000", 1000, 1000)
		},
		"bad ref block": func() (string, error) {
			return BuildTronTransactionWithRefBlock(from, to, 1, "zz", "8fa9e75800000000", 2000, 1000)
		},
	}
	for name, call := range errCases {
		if _, err := call(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestErrors(t *testing.T) {
	keyshares := keygen(t, 2, 2)
	dkg, err := NewDKLS23DKGState(0, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer dkg.Free()
	dsg, err := NewDKLS23DSGState(keyshares[0], "m")
	if err != nil {
		t.Fatal(err)
	}
	defer dsg.Free()

	validHash := strings.Repeat("ab", 32)
	tests := map[string]func() error{
		"negative party":         func() error { _, err := NewDKLS23DKGState(-1, 2, 2); return err },
		"party above 255":        func() error { _, err := NewDKLS23DKGState(256, 300, 2); return err },
		"party out of range":     func() error { _, err := NewDKLS23DKGState(2, 2, 2); return err },
		"bad DSG keyshare":       func() error { _, err := NewDKLS23DSGState("{}", "m"); return err },
		"DKG msg1 not array":     func() error { _, err := dkg.HandleMsg1(`{}`); return err },
		"DKG msg2 not array":     func() error { _, err := dkg.HandleMsg2(`x`); return err },
		"DKG msg3 not array":     func() error { _, err := dkg.HandleMsg3(`x`, `[]`); return err },
		"DKG commitments object": func() error { _, err := dkg.HandleMsg3(`[]`, `{}`); return err },
		"DKG msg4 not array":     func() error { _, err := dkg.HandleMsg4(`x`); return err },
		"DSG msg1 not array":     func() error { _, err := dsg.HandleMsg1(`x`); return err },
		"DSG msg2 not array":     func() error { _, err := dsg.HandleMsg2(`x`); return err },
		"DSG msg3 not array":     func() error { _, err := dsg.HandleMsg3(`x`); return err },
		"hash not hex":           func() error { _, err := DKLS23CreatePartialSignature(`{}`, "zz"); return err },
		"hash too short":         func() error { _, err := DKLS23CreatePartialSignature(`{}`, "abcd"); return err },
		"hash too long":          func() error { _, err := DKLS23CreatePartialSignature(`{}`, validHash+"00"); return err },
		"hash odd length":        func() error { _, err := DKLS23CreatePartialSignature(`{}`, validHash[1:]); return err },
		"unknown presignature": func() error {
			_, err := DKLS23CreatePartialSignature(`{"presignature_handle":"00"}`, validHash)
			return err
		},
		"combine msg4 not array": func() error { _, err := DKLS23CombineSignatures(`{}`, `x`); return err },
		"combine bad partial":    func() error { _, err := DKLS23CombineSignatures(`{}`, `[]`); return err },
		"derive bad path":        func() error { _, err := DKLS23DerivePublicKey(keyshares[0], "q"); return err },
		"derive keyshare bad":    func() error { _, err := DKLS23DeriveKeyshare("{}", "m/1"); return err },
		"tron bad hex":           func() error { _, err := PublicKeyToTronAddress("xyz"); return err },
		"tron wrong length":      func() error { _, err := PublicKeyToTronAddress("02ab"); return err },
		"eth bad key":            func() error { _, err := PublicKeyToEthereumAddress("02ab"); return err },
		"btc bad key":            func() error { _, err := PublicKeyToBitcoinAddress("02ab", true); return err },
		"segwit bad key":         func() error { _, err := PublicKeyToBitcoinSegWitAddress("02ab", true); return err },
	}
	for name, call := range tests {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}

	// Calls on freed states fail instead of crashing.
	dkg.Free()
	dkg.Free()
	if _, err := dkg.GenerateMsg1(); err == nil {
		t.Error("GenerateMsg1 on freed DKG state must fail")
	}
	if _, err := dkg.CalculateCommitment2(); err == nil {
		t.Error("CalculateCommitment2 on freed DKG state must fail")
	}
	dsg.Free()
	dsg.Free()
	if _, err := dsg.GenerateMsg1(); err == nil {
		t.Error("GenerateMsg1 on freed DSG state must fail")
	}
}
