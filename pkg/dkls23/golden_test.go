package dkls23

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenDir holds the DKLs23 wire-format fixtures shared with the Rust
// golden tests (internal/rust/ffi/src/ffi_tests/golden.rs). They are
// throwaway test keys; see the README.md there for how to regenerate them.
var goldenDir = filepath.Join("..", "..", "internal", "rust", "ffi", "testdata", "golden")

type goldenSet struct {
	Files            []string `json:"files"`
	PublicKey        string   `json:"public_key"`
	DerivedPublicKey string   `json:"derived_public_key"`
}

type goldenExpected struct {
	DerivationPath string               `json:"derivation_path"`
	Sets           map[string]goldenSet `json:"sets"`
	Signing        struct {
		KeyshareSet string   `json:"keyshare_set"`
		MessageHash string   `json:"message_hash"`
		Partials    []string `json:"partials"`
		Signature   string   `json:"signature"`
	} `json:"signing"`
}

func readGolden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name))
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func loadGoldenExpected(t *testing.T) goldenExpected {
	t.Helper()
	var exp goldenExpected
	if err := json.Unmarshal([]byte(readGolden(t, "expected.json")), &exp); err != nil {
		t.Fatalf("decode expected.json: %v", err)
	}
	return exp
}

// TestGoldenKeysharesSign checks that keyshares stored by an earlier release
// still derive the stored public keys and sign through the Go bindings, with
// signatures verified by the independent decred implementation.
func TestGoldenKeysharesSign(t *testing.T) {
	exp := loadGoldenExpected(t)
	// Signing takes exactly threshold (2) parties; ranks [0,1,1] cannot
	// sign with the pair {1, 2}.
	pairs := map[string][][2]int{
		"2of3":   {{0, 1}, {0, 2}, {1, 2}},
		"ranked": {{0, 1}, {0, 2}},
	}
	for name, signerPairs := range pairs {
		set, ok := exp.Sets[name]
		if !ok || len(set.Files) != 3 {
			t.Fatalf("expected.json has no 3-party set %q", name)
		}
		keyshares := make([]string, len(set.Files))
		for i, f := range set.Files {
			keyshares[i] = readGolden(t, f)
			if got := keysharePublicKey(t, keyshares[i]); !strings.EqualFold(got, set.PublicKey) {
				t.Errorf("%s: public_key field %s, want %s", f, got, set.PublicKey)
			}
			for path, want := range map[string]string{"m": set.PublicKey, exp.DerivationPath: set.DerivedPublicKey} {
				got, err := DeriveChildPublicKey(keyshares[i], path)
				if err != nil {
					t.Fatalf("%s: derive %s: %v", f, path, err)
				}
				if got != want {
					t.Errorf("%s: public key at %s is %s, want %s", f, path, got, want)
				}
			}
		}
		for _, pair := range signerPairs {
			signers := []string{keyshares[pair[0]], keyshares[pair[1]]}
			for path, pub := range map[string]string{"m": set.PublicKey, exp.DerivationPath: set.DerivedPublicKey} {
				t.Run(fmt.Sprintf("%s/%v/%s", name, pair, path), func(t *testing.T) {
					hash := sha256.Sum256([]byte(fmt.Sprintf("go golden %s %v %s", name, pair, path)))
					verifyECDSA(t, pub, runDSG(t, signers, path, hash), hash)
				})
			}
		}
	}
}

// TestGoldenPartialsCombine replays stored partial signatures through
// CombineSignatures; combining is deterministic, so the result must be the
// stored signature byte for byte.
func TestGoldenPartialsCombine(t *testing.T) {
	exp := loadGoldenExpected(t)
	hashBytes, err := hex.DecodeString(exp.Signing.MessageHash)
	if err != nil || len(hashBytes) != 32 {
		t.Fatalf("bad message_hash %q: %v", exp.Signing.MessageHash, err)
	}
	var hash [32]byte
	copy(hash[:], hashBytes)

	partials := make([]struct {
		Partial json.RawMessage `json:"partial"`
		Msg4    json.RawMessage `json:"msg4"`
	}, len(exp.Signing.Partials))
	for i, f := range exp.Signing.Partials {
		if err := json.Unmarshal([]byte(readGolden(t, f)), &partials[i]); err != nil {
			t.Fatalf("decode %s: %v", f, err)
		}
	}
	for i := range partials {
		var others []any
		for j, p := range partials {
			if j != i {
				others = append(others, decodeObject(t, string(p.Msg4)))
			}
		}
		sig, err := CombineSignatures(string(partials[i].Partial), others)
		if err != nil {
			t.Fatalf("combine as signer %d: %v", i, err)
		}
		if sig != exp.Signing.Signature {
			t.Errorf("combine as signer %d: got %s, want %s", i, sig, exp.Signing.Signature)
		}
	}
	verifyECDSA(t, exp.Sets[exp.Signing.KeyshareSet].PublicKey, exp.Signing.Signature, hash)
}
