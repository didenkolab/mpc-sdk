package frost

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenDir holds the FROST wire-format fixtures shared with the Rust golden
// tests (internal/rust/frost-ffi/src/ffi_tests/golden.rs). They are
// throwaway test keys; see the README.md there for how to regenerate them.
var goldenDir = filepath.Join("..", "..", "internal", "rust", "frost-ffi", "testdata", "golden")

type goldenExpected struct {
	Keyshares []string `json:"keyshares"`
	PublicKey string   `json:"public_key"`
	Signing   struct {
		MessageHex string   `json:"message_hex"`
		Bundles    []string `json:"bundles"`
		Signature  string   `json:"signature"`
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
	if len(exp.Keyshares) != 3 {
		t.Fatalf("expected.json lists %d keyshares, want 3", len(exp.Keyshares))
	}
	return exp
}

// TestGoldenKeysharesSign checks that keyshares stored by an earlier release
// still report the stored group key and sign through the Go bindings, with
// signatures verified by crypto/ed25519.
func TestGoldenKeysharesSign(t *testing.T) {
	exp := loadGoldenExpected(t)
	want, err := hex.DecodeString(exp.PublicKey)
	if err != nil {
		t.Fatalf("decode public_key: %v", err)
	}
	keyshares := make([]string, len(exp.Keyshares))
	for i, f := range exp.Keyshares {
		keyshares[i] = readGolden(t, f)
		if got := groupPublicKey(t, keyshares[i]); !got.Equal(ed25519.PublicKey(want)) {
			t.Errorf("%s: group key %x, want %s", f, got, exp.PublicKey)
		}
	}
	for _, set := range [][]int{{0, 1}, {0, 2}, {1, 2}, {0, 1, 2}} {
		t.Run(fmt.Sprint(set), func(t *testing.T) {
			signers := make([]string, len(set))
			for i, idx := range set {
				signers[i] = keyshares[idx]
			}
			message := []byte(fmt.Sprintf("go golden signers %v", set))
			sig, err := hex.DecodeString(sign(t, signers, message))
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			if !ed25519.Verify(want, message, sig) {
				t.Fatal("signature does not verify against the stored group key")
			}
		})
	}
}

// TestGoldenBundlesCombine replays stored signature share bundles through
// CombineSignatures; aggregation is deterministic, so the result must be the
// stored signature byte for byte.
func TestGoldenBundlesCombine(t *testing.T) {
	exp := loadGoldenExpected(t)
	bundles := make([]string, len(exp.Signing.Bundles))
	for i, f := range exp.Signing.Bundles {
		bundles[i] = readGolden(t, f)
	}
	for i := range bundles {
		sig, err := CombineSignatures(bundles[i], othersOf(bundles, i))
		if err != nil {
			t.Fatalf("combine as signer %d: %v", i, err)
		}
		if sig != exp.Signing.Signature {
			t.Errorf("combine as signer %d: got %s, want %s", i, sig, exp.Signing.Signature)
		}
	}
	message, err := hex.DecodeString(exp.Signing.MessageHex)
	if err != nil {
		t.Fatalf("decode message_hex: %v", err)
	}
	ok, err := VerifySignature(exp.PublicKey, message, exp.Signing.Signature)
	if err != nil || !ok {
		t.Fatalf("stored signature does not verify: ok=%v err=%v", ok, err)
	}
}
