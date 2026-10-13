package evm

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// EIP-155 example transaction (https://eips.ethereum.org/EIPS/eip-155).
var eip155Input = LegacyTxInput{
	Nonce:    9,
	GasPrice: big.NewInt(20_000_000_000),
	GasLimit: 21000,
	To:       "0x3535353535353535353535353535353535353535",
	Value:    new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil),
	ChainID:  big.NewInt(1),
}

const (
	eip155PrivKey     = "4646464646464646464646464646464646464646464646464646464646464646"
	eip155SigningHash = "0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
	eip155SignedTx    = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
)

func mustKey(t *testing.T, hexKey string) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// rsHex returns the r||s part of a 65-byte signature as hex, as produced by
// a threshold signer.
func rsHex(sig []byte) string { return hex.EncodeToString(sig[:64]) }

func TestDeriveAddress(t *testing.T) {
	tests := []struct {
		name    string
		pubHex  string
		want    string
		wantErr bool
	}{
		// Public keys of private keys 1 and 2 (G and 2G).
		{"private key 1", "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf", false},
		{"private key 2", "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF", false},
		{"uncompressed key", "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", "", true},
		{"empty", "", "", true},
		{"not on curve", "02" + strings.Repeat("ff", 32), "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, _ := hex.DecodeString(tc.pubHex)
			got, err := DeriveAddress(pub)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got.Hex() != tc.want {
				t.Errorf("got %s, want %s", got.Hex(), tc.want)
			}
		})
	}
}

func TestBuildUnsignedEIP155Vector(t *testing.T) {
	tx, signer, hash, err := BuildUnsigned(eip155Input)
	if err != nil {
		t.Fatal(err)
	}
	if got := HexHash(hash); got != eip155SigningHash {
		t.Fatalf("signing hash = %s, want %s", got, eip155SigningHash)
	}

	key := mustKey(t, eip155PrivKey)
	raw, err := crypto.Sign(hash[:], key)
	if err != nil {
		t.Fatal(err)
	}
	compressed := crypto.CompressPubkey(&key.PublicKey)

	// Simulate a threshold signer that only outputs r||s.
	sig, err := BuildSignature65(hash, compressed, rsHex(raw))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, raw) {
		t.Fatalf("recovered signature %x, want %x", sig, raw)
	}

	signed, err := AssembleSignature(tx, signer, sig)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := signed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encoded); got != eip155SignedTx {
		t.Fatalf("signed tx =\n%s\nwant\n%s", got, eip155SignedTx)
	}

	sender, err := types.Sender(signer, signed)
	if err != nil {
		t.Fatal(err)
	}
	if want := crypto.PubkeyToAddress(key.PublicKey); sender != want {
		t.Fatalf("sender = %s, want %s", sender.Hex(), want.Hex())
	}
	if signed.ChainId().Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("chain ID = %s, want 1", signed.ChainId())
	}
}

func TestBuildUnsignedValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*LegacyTxInput)
	}{
		{"nil chain ID", func(in *LegacyTxInput) { in.ChainID = nil }},
		{"zero chain ID", func(in *LegacyTxInput) { in.ChainID = big.NewInt(0) }},
		{"negative chain ID", func(in *LegacyTxInput) { in.ChainID = big.NewInt(-1) }},
		{"invalid recipient", func(in *LegacyTxInput) { in.To = "0x1234" }},
		{"empty recipient", func(in *LegacyTxInput) { in.To = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := eip155Input
			tc.mutate(&in)
			if _, _, _, err := BuildUnsigned(in); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestBuildSignature65(t *testing.T) {
	key := mustKey(t, eip155PrivKey)
	pub := crypto.CompressPubkey(&key.PublicKey)
	other := crypto.CompressPubkey(&mustKey(t, strings.Repeat("11", 32)).PublicKey)

	// Find hashes whose signatures use each recovery ID.
	sigs := map[byte][]byte{}
	hashes := map[byte][32]byte{}
	for i := 0; len(sigs) < 2 && i < 64; i++ {
		h := crypto.Keccak256Hash([]byte{byte(i)})
		sig, err := crypto.Sign(h[:], key)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := sigs[sig[64]]; !ok {
			sigs[sig[64]] = sig
			hashes[sig[64]] = h
		}
	}
	if len(sigs) != 2 {
		t.Fatal("could not produce signatures with both recovery IDs")
	}

	for recid, want := range sigs {
		got, err := BuildSignature65(hashes[recid], pub, rsHex(want))
		if err != nil {
			t.Fatalf("recid %d: %v", recid, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("recid %d: got %x, want %x", recid, got, want)
		}
	}

	t.Run("high S is normalized", func(t *testing.T) {
		low := sigs[0]
		hash := hashes[0]
		s := new(big.Int).SetBytes(low[32:64])
		high := make([]byte, 64)
		copy(high, low[:32])
		new(big.Int).Sub(secp256k1N, s).FillBytes(high[32:])

		got, err := BuildSignature65(hash, pub, hex.EncodeToString(high))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, low) {
			t.Fatalf("got %x, want low-S %x", got, low)
		}
		if !crypto.ValidateSignatureValues(got[64], new(big.Int).SetBytes(got[:32]), new(big.Int).SetBytes(got[32:64]), true) {
			t.Fatal("normalized signature is not valid under Homestead rules")
		}
	})

	errCases := []struct {
		name   string
		hash   [32]byte
		pub    []byte
		sigHex string
	}{
		{"wrong public key", hashes[0], other, rsHex(sigs[0])},
		{"wrong hash", [32]byte{1}, pub, rsHex(sigs[0])},
		{"non-hex signature", hashes[0], pub, strings.Repeat("zz", 64)},
		{"short signature", hashes[0], pub, "00"},
		{"invalid public key", hashes[0], []byte{2, 3}, rsHex(sigs[0])},
		{"zero signature", hashes[0], pub, strings.Repeat("00", 64)},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildSignature65(tc.hash, tc.pub, tc.sigHex); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestAssembleSignatureLength(t *testing.T) {
	tx, signer, _, err := BuildUnsigned(eip155Input)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 64, 66} {
		if _, err := AssembleSignature(tx, signer, make([]byte, n)); err == nil {
			t.Errorf("length %d: expected error", n)
		}
	}
}

func TestMakeSignatureBytes(t *testing.T) {
	r := "0x" + strings.Repeat("11", 32)
	s := "0x" + strings.Repeat("22", 32)

	got, err := MakeSignatureBytes(r, s, 1)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString(strings.Repeat("11", 32) + strings.Repeat("22", 32) + "01")
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}

	errCases := []struct{ name, r, s string }{
		{"r missing 0x", strings.Repeat("11", 32), s},
		{"s not hex", r, "0xzz"},
		{"short r", "0x11", s},
		{"long s", r, "0x" + strings.Repeat("22", 33)},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := MakeSignatureBytes(tc.r, tc.s, 0); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSplitRS(t *testing.T) {
	r, s, err := SplitRS(strings.Repeat("aa", 32) + strings.Repeat("bb", 32))
	if err != nil {
		t.Fatal(err)
	}
	if r[0] != 0xaa || r[31] != 0xaa || s[0] != 0xbb || s[31] != 0xbb {
		t.Fatalf("unexpected split: r=%x s=%x", r, s)
	}
	for _, in := range []string{"", "zz", strings.Repeat("aa", 63), strings.Repeat("aa", 65)} {
		if _, _, err := SplitRS(in); err == nil {
			t.Errorf("SplitRS(%q): expected error", in)
		}
	}
}

func TestERC20TransferData(t *testing.T) {
	to := common.HexToAddress("0x3535353535353535353535353535353535353535")
	got, err := ERC20TransferData(to, big.NewInt(1_000_000))
	if err != nil {
		t.Fatal(err)
	}
	want := "a9059cbb" +
		"0000000000000000000000003535353535353535353535353535353535353535" +
		"00000000000000000000000000000000000000000000000000000000000f4240"
	if hex.EncodeToString(got) != want {
		t.Fatalf("calldata =\n%x\nwant\n%s", got, want)
	}

	tooBig := new(big.Int).Lsh(big.NewInt(1), 256)
	for name, amount := range map[string]*big.Int{"nil": nil, "negative": big.NewInt(-1), "overflow": tooBig} {
		if _, err := ERC20TransferData(to, amount); err == nil {
			t.Errorf("%s amount: expected error", name)
		}
	}
}

func TestHexHash(t *testing.T) {
	var h [32]byte
	h[31] = 0xab
	if got, want := HexHash(h), "0x"+strings.Repeat("00", 31)+"ab"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestParseAddress(t *testing.T) {
	const checksummed = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"checksummed", checksummed, false},
		{"lower case", strings.ToLower(checksummed), false},
		{"upper case body", "0x" + strings.ToUpper(checksummed[2:]), false},
		{"bad checksum", "0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf", true},
		{"missing 0x", checksummed[2:], true},
		{"too short", checksummed[:40], true},
		{"too long", checksummed + "00", true},
		{"not hex", "0x" + strings.Repeat("zz", 20), true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := ParseAddress(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseAddress(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if err == nil && addr.Hex() != checksummed {
				t.Fatalf("ParseAddress(%q) = %s, want %s", tt.in, addr.Hex(), checksummed)
			}
		})
	}
}
