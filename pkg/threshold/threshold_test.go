package threshold

import (
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestSignatureAlgorithmString(t *testing.T) {
	tests := map[SignatureAlgorithm]string{
		Ed25519FROST:           "Ed25519-FROST",
		ECDSASecp256k1:         "ECDSA-Secp256k1-DKLs23",
		SignatureAlgorithm(42): "Unknown-42",
	}
	for alg, want := range tests {
		if got := alg.String(); got != want {
			t.Errorf("%d: got %q, want %q", int(alg), got, want)
		}
	}
}

func TestThresholdConfigValidate(t *testing.T) {
	transport := NewInMemoryTransport()
	valid := ThresholdConfig{Participants: 3, Threshold: 2, PartyID: 2, SessionID: "s", Transport: transport}
	tests := []struct {
		name    string
		mutate  func(*ThresholdConfig)
		wantErr string
	}{
		{"valid prod", func(*ThresholdConfig) {}, ""},
		{"valid demo without transport", func(c *ThresholdConfig) {
			c.Mode, c.SessionID, c.Transport = ExecutionModeInMemoryDemo, "", nil
		}, ""},
		{"one participant", func(c *ThresholdConfig) { c.Participants = 1 }, "participants must be >= 2"},
		{"too many participants", func(c *ThresholdConfig) { c.Participants = 300 }, "participants must be <="},
		{"zero threshold", func(c *ThresholdConfig) { c.Threshold = 0 }, "threshold must be >= 1"},
		{"threshold above n", func(c *ThresholdConfig) { c.Threshold = 4 }, "cannot exceed"},
		{"party out of range", func(c *ThresholdConfig) { c.PartyID = 3 }, "party_id"},
		{"prod without session", func(c *ThresholdConfig) { c.SessionID = "" }, "session_id"},
		{"prod without transport", func(c *ThresholdConfig) { c.Transport = nil }, "transport"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.mutate(&c)
			err := c.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestGetOperation(t *testing.T) {
	m := NewThresholdManager()
	for _, alg := range algorithms {
		op, err := m.GetOperation(alg)
		if err != nil || op.GetAlgorithm() != alg {
			t.Fatalf("%s: %v, %v", alg, op, err)
		}
	}
	if _, err := m.GetOperation(SignatureAlgorithm(9)); err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
	if _, err := m.CreateThresholdKeys(SignatureAlgorithm(9), 2, 2, 0); err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestGenerateThresholdKeysErrors(t *testing.T) {
	for _, alg := range algorithms {
		op, _ := NewThresholdManager().GetOperation(alg)
		other := Ed25519FROST
		if alg == Ed25519FROST {
			other = ECDSASecp256k1
		}
		tests := []struct {
			name string
			cfg  *ThresholdConfig
		}{
			{"nil config", nil},
			{"wrong algorithm", &ThresholdConfig{Algorithm: other, Participants: 2, Threshold: 2, Mode: ExecutionModeInMemoryDemo}},
			{"invalid config", &ThresholdConfig{Algorithm: alg, Participants: 1, Threshold: 1, Mode: ExecutionModeInMemoryDemo}},
			{"prod without transport", &ThresholdConfig{Algorithm: alg, Participants: 2, Threshold: 2, SessionID: "s"}},
			{"threshold one", &ThresholdConfig{Algorithm: alg, Participants: 2, Threshold: 1, Mode: ExecutionModeInMemoryDemo}},
		}
		for _, tc := range tests {
			t.Run(alg.String()+"/"+tc.name, func(t *testing.T) {
				if _, err := op.GenerateThresholdKeys(tc.cfg); err == nil {
					t.Fatal("expected an error")
				}
			})
		}
	}
}

// TestProdModeDKG runs one WalletManager per party, as separate nodes would,
// connected through a shared transport.
func TestProdModeDKG(t *testing.T) {
	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			const n, threshold = 3, 2
			transport := NewInMemoryTransport()
			shares := make([]*KeyShare, n)
			errs := make([]error, n)
			var wg sync.WaitGroup
			for i := range n {
				wm := NewWalletManager(alg)
				wm.SetTransport(transport)
				wg.Add(1)
				go func() {
					defer wg.Done()
					res, err := wm.GenerateThresholdKeys(&ThresholdConfig{
						Algorithm:    alg,
						Participants: n,
						Threshold:    threshold,
						PartyID:      uint8(i),
						SessionID:    "prod-" + alg.String(),
					})
					if err == nil && len(res) != 1 {
						err = errors.New("prod mode must return exactly one share")
					}
					if err == nil {
						shares[i] = res[0]
					}
					errs[i] = err
				}()
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("party %d: %v", i, err)
				}
			}
			checkShares(t, shares, n, threshold)

			// In prod mode a single process must not sign with a quorum.
			wm := NewWalletManager(alg)
			if _, err := wm.SignMessage([]byte("x"), shares, []int{0, 1}); err == nil {
				t.Fatal("prod mode must refuse local multi-share signing")
			}
			if _, err := wm.SignMessage([]byte("x"), shares[:1], []int{0}); err == nil {
				t.Fatal("prod mode must refuse local signing of a threshold key")
			}
			addr, err := wm.GenerateAddress(shares[0], "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := wm.SignTransaction(make([]byte, 32), shares, []int{0, 1}, addr); err == nil {
				t.Fatal("prod mode must refuse local transaction signing")
			}
		})
	}
}

func TestWalletManagerGenerateThresholdKeysErrors(t *testing.T) {
	wm := NewWalletManager(ECDSASecp256k1)
	if _, err := wm.GenerateThresholdKeys(nil); err == nil {
		t.Error("expected error for nil config")
	}
	if _, err := wm.GenerateThresholdKeys(&ThresholdConfig{Algorithm: Ed25519FROST, Participants: 2, Threshold: 2}); err == nil {
		t.Error("expected algorithm mismatch")
	}
	if _, err := wm.GenerateThresholdKeys(&ThresholdConfig{Algorithm: ECDSASecp256k1, Participants: 2, Threshold: 2}); err == nil ||
		!strings.Contains(err.Error(), "session_id") {
		t.Errorf("expected session_id error, got %v", err)
	}
	if _, err := wm.CreateCompleteWallet(2, 2, 0); err == nil {
		t.Error("CreateCompleteWallet in prod mode without session must fail")
	}
}

func TestCompleteWallet(t *testing.T) {
	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			wm := NewWalletManagerWithMode(alg, ExecutionModeInMemoryDemo)
			if wm.GetAlgorithm() != alg {
				t.Fatalf("GetAlgorithm = %s", wm.GetAlgorithm())
			}
			wallet, err := wm.CreateCompleteWallet(3, 2, 1)
			if err != nil {
				t.Fatal(err)
			}
			checkShares(t, wallet.KeyShares, 3, 2)
			if wallet.Algorithm != alg || wallet.MainAddress == nil || wallet.MainAddress.Address == "" {
				t.Fatalf("unexpected wallet %+v", wallet)
			}

			if got := wallet.GetAvailableSigners(); len(got) != 3 || got[0] != 0 || got[2] != 2 {
				t.Fatalf("GetAvailableSigners = %v", got)
			}
			canSign := map[string]struct {
				signers []int
				want    bool
			}{
				"quorum":     {[]int{0, 2}, true},
				"all":        {[]int{0, 1, 2}, true},
				"too few":    {[]int{1}, false},
				"duplicates": {[]int{1, 1}, false},
				"out of range": {
					[]int{0, 3}, false,
				},
				"negative": {[]int{-1, 0}, false},
			}
			for name, tc := range canSign {
				if got := wallet.CanSign(tc.signers); got != tc.want {
					t.Errorf("CanSign %s (%v) = %v, want %v", name, tc.signers, got, tc.want)
				}
			}

			msg := []byte("wallet message")
			sig, err := wallet.SignWithWallet(msg, []int{2, 1}, wm)
			if err != nil {
				t.Fatal(err)
			}
			verifyIndependently(t, sig, wallet.MainAddress.PublicKey, sha256.Sum256(msg))
			if ok, err := wm.VerifySignature(msg, sig); err != nil || !ok {
				t.Fatalf("VerifySignature = %v, %v", ok, err)
			}
			if _, err := wm.VerifySignature(msg, nil); err == nil {
				t.Fatal("expected error for nil signature")
			}

			balance, err := wm.GetBalance(wallet.MainAddress)
			if err != nil || balance == "" {
				t.Fatalf("demo balance = %q, %v", balance, err)
			}
		})
	}
}

// TestSignTransactionSignsDigestAsIs checks that the transaction digest is
// signed directly, as blockchains expect, rather than hashed again.
func TestSignTransactionSignsDigestAsIs(t *testing.T) {
	for _, alg := range algorithms {
		t.Run(alg.String(), func(t *testing.T) {
			wm := NewWalletManagerWithMode(alg, ExecutionModeInMemoryDemo)
			wallet, err := wm.CreateCompleteWallet(3, 2, 0)
			if err != nil {
				t.Fatal(err)
			}
			txHash := sha256.Sum256([]byte("raw transaction bytes"))
			sig, err := wm.SignTransaction(txHash[:], wallet.KeyShares, []int{0, 2}, wallet.MainAddress)
			if err != nil {
				t.Fatal(err)
			}
			verifyIndependently(t, sig, wallet.MainAddress.PublicKey, txHash)

			ok, err := wm.VerifyTransactionSignature(txHash[:], sig)
			if err != nil || !ok {
				t.Fatalf("VerifyTransactionSignature = %v, %v", ok, err)
			}
			other := sha256.Sum256([]byte("other"))
			if ok, _ := wm.VerifyTransactionSignature(other[:], sig); ok {
				t.Fatal("signature verified for another digest")
			}

			if _, err := wm.SignTransaction(txHash[:31], wallet.KeyShares, []int{0, 1}, wallet.MainAddress); err == nil {
				t.Fatal("expected error for short digest")
			}
			if _, err := wm.SignTransaction(txHash[:], wallet.KeyShares, []int{0, 1}, nil); err == nil {
				t.Fatal("expected error for nil address")
			}
			wrong := *wallet.MainAddress
			wrong.Algorithm = SignatureAlgorithm(7)
			if _, err := wm.SignTransaction(txHash[:], wallet.KeyShares, []int{0, 1}, &wrong); err == nil {
				t.Fatal("expected error for address algorithm mismatch")
			}
			if _, err := wm.VerifyTransactionSignature(txHash[:5], sig); err == nil {
				t.Fatal("expected error for short digest")
			}
			if _, err := wm.VerifyTransactionSignature(txHash[:], nil); err == nil {
				t.Fatal("expected error for nil signature")
			}
			bad := *sig
			bad.Algorithm = SignatureAlgorithm(7)
			if _, err := wm.VerifyTransactionSignature(txHash[:], &bad); err == nil {
				t.Fatal("expected error for unknown algorithm")
			}
		})
	}
}

func TestGenerateAddress(t *testing.T) {
	const (
		// Public key of secp256k1 private key 1 (the generator point).
		secpG = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
		// RFC 8032 test vector 1 public key.
		edPub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	)
	ecdsaKey := &KeyShare{Algorithm: ECDSASecp256k1, PublicKey: secpG, Path: "m/0"}
	edKey := &KeyShare{Algorithm: Ed25519FROST, PublicKey: edPub}

	tests := []struct {
		alg     SignatureAlgorithm
		key     *KeyShare
		typ     string
		want    string
		wantErr bool
	}{
		{ECDSASecp256k1, ecdsaKey, "", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", false},
		{ECDSASecp256k1, ecdsaKey, "btc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", false},
		{ECDSASecp256k1, ecdsaKey, "bitcoin-legacy", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", false},
		{ECDSASecp256k1, ecdsaKey, "eth", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", false},
		{ECDSASecp256k1, ecdsaKey, "bsc", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", false},
		{ECDSASecp256k1, ecdsaKey, "polygon", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", false},
		{ECDSASecp256k1, ecdsaKey, "solana", "", true},
		{ECDSASecp256k1, edKey, "eth", "", true},
		{ECDSASecp256k1, &KeyShare{Algorithm: ECDSASecp256k1, PublicKey: edPub}, "eth", "", true},
		{ECDSASecp256k1, &KeyShare{Algorithm: ECDSASecp256k1, PublicKey: "zz"}, "eth", "", true},
		{ECDSASecp256k1, nil, "eth", "", true},
		{Ed25519FROST, edKey, "", "FVen3X669xLzsi6N2V91DoiyzHzg1uAgqiT8jZ9nS96Z", false},
		{Ed25519FROST, edKey, "near", edPub, false},
		{Ed25519FROST, edKey, "eth", "", true},
		{Ed25519FROST, &KeyShare{Algorithm: Ed25519FROST, PublicKey: secpG}, "solana", "", true},
		{SignatureAlgorithm(9), &KeyShare{Algorithm: SignatureAlgorithm(9), PublicKey: edPub}, "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.alg.String()+"/"+tc.typ, func(t *testing.T) {
			addr, err := NewWalletManagerWithMode(tc.alg, ExecutionModeInMemoryDemo).GenerateAddress(tc.key, tc.typ)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", addr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if addr.Address != tc.want || addr.Algorithm != tc.alg || addr.PublicKey != tc.key.PublicKey || addr.Path != tc.key.Path {
				t.Fatalf("got %+v, want address %s", addr, tc.want)
			}
		})
	}
}

type fixedBalance string

func (b fixedBalance) Balance(*WalletAddress) (string, error) { return string(b), nil }

func TestGetBalance(t *testing.T) {
	addr := &WalletAddress{Algorithm: ECDSASecp256k1, Address: "x"}

	prod := NewWalletManager(ECDSASecp256k1)
	if _, err := prod.GetBalance(addr); err == nil {
		t.Error("prod mode without provider must fail")
	}
	if _, err := prod.GetBalance(nil); err == nil {
		t.Error("nil address must fail")
	}
	prod.SetBalanceProvider(fixedBalance("42"))
	if got, err := prod.GetBalance(addr); err != nil || got != "42" {
		t.Errorf("provider balance = %q, %v", got, err)
	}

	demo := NewWalletManagerWithMode(ECDSASecp256k1, ExecutionModeInMemoryDemo)
	for _, alg := range algorithms {
		if got, err := demo.GetBalance(&WalletAddress{Algorithm: alg}); err != nil || got == "" {
			t.Errorf("%s demo balance = %q, %v", alg, got, err)
		}
	}
	if _, err := demo.GetBalance(&WalletAddress{Algorithm: SignatureAlgorithm(9)}); err == nil {
		t.Error("unknown algorithm must fail")
	}
}

func TestWalletManagerDeriveChildKey(t *testing.T) {
	wm := NewWalletManagerWithMode(ECDSASecp256k1, ExecutionModeInMemoryDemo)
	if _, err := wm.DeriveChildKey(nil, "m/0"); err == nil {
		t.Error("expected error for nil share")
	}
	if _, err := wm.DeriveChildKey(&KeyShare{Algorithm: SignatureAlgorithm(9)}, "m/0"); err == nil {
		t.Error("expected error for unknown algorithm")
	}
	shares := demoKeys(t, ECDSASecp256k1, 2, 2)
	child, err := wm.DeriveChildKey(shares[0], "m/1")
	if err != nil || child.Path != "m/1" || child.PublicKey == shares[0].PublicKey {
		t.Fatalf("DeriveChildKey = %+v, %v", child, err)
	}
}
