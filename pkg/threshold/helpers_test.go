package threshold

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var algorithms = []SignatureAlgorithm{ECDSASecp256k1, Ed25519FROST}

// demoKeys generates all keyshares of an n-party key in this process.
func demoKeys(t *testing.T, alg SignatureAlgorithm, n, threshold int) []*KeyShare {
	t.Helper()
	shares, err := NewThresholdManager().CreateThresholdKeys(alg, n, threshold, 0)
	if err != nil {
		t.Fatalf("%s %d-of-%d key generation: %v", alg, threshold, n, err)
	}
	checkShares(t, shares, n, threshold)
	return shares
}

// checkShares asserts that shares belong to one key and are indexed by party.
func checkShares(t *testing.T, shares []*KeyShare, n, threshold int) {
	t.Helper()
	if len(shares) != n {
		t.Fatalf("got %d keyshares, want %d", len(shares), n)
	}
	for i, ks := range shares {
		if ks.PartyID != uint8(i) {
			t.Errorf("share %d has PartyID %d", i, ks.PartyID)
		}
		if ks.Participants != n || ks.Threshold != threshold {
			t.Errorf("share %d is %d-of-%d, want %d-of-%d", i, ks.Threshold, ks.Participants, threshold, n)
		}
		if ks.PublicKey != shares[0].PublicKey {
			t.Errorf("share %d public key %s, want %s", i, ks.PublicKey, shares[0].PublicKey)
		}
		if ks.KeyData == "" {
			t.Errorf("share %d has no key data", i)
		}
		if ks.Path != "m" {
			t.Errorf("share %d has path %q, want m", i, ks.Path)
		}
	}
}

// verifyIndependently checks sig over digest with a library unrelated to the
// signing code: decred secp256k1 for ECDSA, crypto/ed25519 for FROST.
func verifyIndependently(t *testing.T, sig *Signature, publicKeyHex string, digest [32]byte) {
	t.Helper()
	if !equalHex(sig.PublicKey, publicKeyHex) {
		t.Fatalf("signature carries public key %s, want %s", sig.PublicKey, publicKeyHex)
	}
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(sig.Data) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(sig.Data))
	}

	switch sig.Algorithm {
	case ECDSASecp256k1:
		pk, err := secp.ParsePubKey(pub)
		if err != nil {
			t.Fatalf("parse public key: %v", err)
		}
		var r, s secp.ModNScalar
		r.SetByteSlice(sig.Data[:32])
		s.SetByteSlice(sig.Data[32:])
		if hex.EncodeToString(sig.Data[:32]) != sig.R || hex.EncodeToString(sig.Data[32:]) != sig.S {
			t.Fatal("R/S do not match signature data")
		}
		if !secpecdsa.NewSignature(&r, &s).Verify(digest[:], pk) {
			t.Fatal("ECDSA signature rejected by decred secp256k1")
		}
	case Ed25519FROST:
		if !ed25519.Verify(pub, digest[:], sig.Data) {
			t.Fatal("Ed25519 signature rejected by crypto/ed25519")
		}
	default:
		t.Fatalf("unknown algorithm %s", sig.Algorithm)
	}
}
