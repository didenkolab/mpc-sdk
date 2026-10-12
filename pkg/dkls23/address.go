package dkls23

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// parsePublicKey decodes a hex-encoded compressed (33-byte) or uncompressed
// (65-byte) secp256k1 public key.
func parsePublicKey(publicKeyHex string) (*secp.PublicKey, error) {
	pubKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex public key: %w", err)
	}
	pubKey, err := secp.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return pubKey, nil
}

func bitcoinParams(mainnet bool) *chaincfg.Params {
	if mainnet {
		return &chaincfg.MainNetParams
	}
	return &chaincfg.TestNet3Params
}

// PublicKeyToEthereumAddress converts a hex-encoded secp256k1 public key
// (compressed or uncompressed) to a lowercase 0x-prefixed Ethereum address.
func PublicKeyToEthereumAddress(publicKeyHex string) (string, error) {
	pubKey, err := parsePublicKey(publicKeyHex)
	if err != nil {
		return "", err
	}

	// The address is the last 20 bytes of Keccak-256(X || Y).
	uncompressed := pubKey.SerializeUncompressed()
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(uncompressed[1:])
	hash := hasher.Sum(nil)

	return "0x" + hex.EncodeToString(hash[12:]), nil
}

// PublicKeyToBitcoinAddress converts a hex-encoded secp256k1 public key to a
// legacy P2PKH address ("1..." on mainnet, "m..."/"n..." on testnet).
func PublicKeyToBitcoinAddress(publicKeyHex string, mainnet bool) (string, error) {
	pubKey, err := parsePublicKey(publicKeyHex)
	if err != nil {
		return "", err
	}

	addr, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		bitcoinParams(mainnet),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create address: %w", err)
	}
	return addr.EncodeAddress(), nil
}

// PublicKeyToBitcoinSegWitAddress converts a hex-encoded secp256k1 public key
// to a native SegWit P2WPKH address ("bc1..." on mainnet, "tb1..." on testnet).
func PublicKeyToBitcoinSegWitAddress(publicKeyHex string, mainnet bool) (string, error) {
	pubKey, err := parsePublicKey(publicKeyHex)
	if err != nil {
		return "", err
	}

	addr, err := btcutil.NewAddressWitnessPubKeyHash(
		btcutil.Hash160(pubKey.SerializeCompressed()),
		bitcoinParams(mainnet),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create segwit address: %w", err)
	}
	return addr.EncodeAddress(), nil
}
