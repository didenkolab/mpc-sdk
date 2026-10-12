package dkls23

import (
	"strings"
	"testing"
)

// The secp256k1 generator point G, i.e. the public key of private key 1.
const (
	generatorCompressed   = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	generatorUncompressed = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
		"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)

func TestAddresses(t *testing.T) {
	tests := []struct {
		name string
		fn   func(string) (string, error)
		want string
	}{
		{"ethereum", PublicKeyToEthereumAddress, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"},
		{"bitcoin mainnet", func(k string) (string, error) { return PublicKeyToBitcoinAddress(k, true) }, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"},
		{"bitcoin testnet", func(k string) (string, error) { return PublicKeyToBitcoinAddress(k, false) }, "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r"},
		{"segwit mainnet", func(k string) (string, error) { return PublicKeyToBitcoinSegWitAddress(k, true) }, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		{"segwit testnet", func(k string) (string, error) { return PublicKeyToBitcoinSegWitAddress(k, false) }, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{generatorCompressed, generatorUncompressed} {
				got, err := tc.fn(key)
				if err != nil {
					t.Fatalf("key %s...: %v", key[:8], err)
				}
				if got != tc.want {
					t.Fatalf("key %s...: got %s, want %s", key[:8], got, tc.want)
				}
			}
			for _, bad := range []string{"zz", "02" + strings.Repeat("00", 32), ""} {
				if _, err := tc.fn(bad); err == nil {
					t.Errorf("expected error for public key %q", bad)
				}
			}
		})
	}
}
