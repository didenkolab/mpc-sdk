// Package evm contains helpers shared by EVM-compatible chains (Ethereum,
// BSC, Polygon, Arbitrum, Avalanche C-Chain): address derivation, EIP-155
// transaction building, and turning a raw threshold ECDSA signature (r||s)
// into the 65-byte form expected by go-ethereum.
package evm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	secp256k1N     = crypto.S256().Params().N
	secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)

	// erc20TransferSelector is the 4-byte selector of transfer(address,uint256).
	erc20TransferSelector = []byte{0xa9, 0x05, 0x9c, 0xbb}
)

// LegacyTxInput describes a legacy (pre-EIP-1559) transaction.
type LegacyTxInput struct {
	Nonce    uint64
	GasPrice *big.Int
	GasLimit uint64
	To       string
	Value    *big.Int
	Data     []byte
	ChainID  *big.Int
}

// ParseAddress parses a 0x-prefixed 20-byte hex address. Unlike
// common.HexToAddress it never truncates or pads: malformed input is an
// error. Mixed-case input must carry a valid EIP-55 checksum, so a typo in a
// checksummed address is caught instead of silently sending funds elsewhere.
func ParseAddress(s string) (common.Address, error) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return common.Address{}, fmt.Errorf("evm: address %q must start with 0x", s)
	}
	if !common.IsHexAddress(s) {
		return common.Address{}, fmt.Errorf("evm: invalid address %q", s)
	}
	addr := common.HexToAddress(s)
	body := s[2:]
	if body != strings.ToLower(body) && body != strings.ToUpper(body) && addr.Hex()[2:] != body {
		return common.Address{}, fmt.Errorf("evm: address %q has an invalid EIP-55 checksum", s)
	}
	return addr, nil
}

// BuildUnsigned creates a legacy transaction together with its EIP-155
// signer and the 32-byte hash that has to be signed.
func BuildUnsigned(in LegacyTxInput) (*types.Transaction, types.Signer, [32]byte, error) {
	if in.ChainID == nil || in.ChainID.Sign() <= 0 {
		return nil, nil, [32]byte{}, errors.New("evm: chain ID must be positive")
	}
	to, err := ParseAddress(in.To)
	if err != nil {
		return nil, nil, [32]byte{}, fmt.Errorf("evm: invalid recipient: %w", err)
	}
	tx := types.NewTransaction(in.Nonce, to, in.Value, in.GasLimit, in.GasPrice, in.Data)
	signer := types.NewEIP155Signer(in.ChainID)
	return tx, signer, signer.Hash(tx), nil
}

// AssembleSignature attaches a 65-byte R|S|V signature to tx, where V is the
// recovery ID (0 or 1). The signer adjusts V for EIP-155.
func AssembleSignature(tx *types.Transaction, signer types.Signer, sig []byte) (*types.Transaction, error) {
	if len(sig) != crypto.SignatureLength {
		return nil, errors.New("evm: signature must be 65 bytes")
	}
	return tx.WithSignature(signer, sig)
}

// DeriveAddress returns the EVM address of a 33-byte compressed secp256k1
// public key.
func DeriveAddress(compressedPub []byte) (common.Address, error) {
	if len(compressedPub) != 33 {
		return common.Address{}, errors.New("evm: compressed public key must be 33 bytes")
	}
	pk, err := crypto.DecompressPubkey(compressedPub)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pk), nil
}

// MakeSignatureBytes builds a 65-byte R|S|V signature from 0x-prefixed hex R
// and S values and the recovery ID v.
func MakeSignatureBytes(rHex, sHex string, v byte) ([]byte, error) {
	r, err := hexutil.Decode(rHex)
	if err != nil {
		return nil, err
	}
	s, err := hexutil.Decode(sHex)
	if err != nil {
		return nil, err
	}
	if len(r) != 32 || len(s) != 32 {
		return nil, errors.New("evm: r and s must be 32 bytes")
	}
	out := make([]byte, crypto.SignatureLength)
	copy(out[:32], r)
	copy(out[32:64], s)
	out[64] = v
	return out, nil
}

// SplitRS splits a hex-encoded 64-byte signature (r||s) into its components.
func SplitRS(sigHex string) ([32]byte, [32]byte, error) {
	var r, s [32]byte
	b, err := hex.DecodeString(sigHex)
	if err != nil {
		return r, s, err
	}
	if len(b) != 64 {
		return r, s, errors.New("evm: signature must be 64 bytes (r||s)")
	}
	copy(r[:], b[:32])
	copy(s[:], b[32:])
	return r, s, nil
}

// BuildSignature65 converts a hex r||s signature over hash into the 65-byte
// R|S|V form, where V is the recovery ID (0 or 1, not EIP-155 adjusted).
//
// Threshold ECDSA does not know the recovery ID, so it is found by trying
// every candidate against compressedPub. A high-S signature is normalized to
// low S (EIP-2), which Ethereum requires for transaction signatures.
func BuildSignature65(hash [32]byte, compressedPub []byte, sigHex string) ([]byte, error) {
	r, s, err := SplitRS(sigHex)
	if err != nil {
		return nil, err
	}
	pk, err := crypto.DecompressPubkey(compressedPub)
	if err != nil {
		return nil, err
	}
	target := crypto.FromECDSAPub(pk)

	sVal := new(big.Int).SetBytes(s[:])
	if sVal.Cmp(secp256k1HalfN) > 0 {
		sVal.Sub(secp256k1N, sVal)
		sVal.FillBytes(s[:])
	}

	sig := make([]byte, crypto.SignatureLength)
	copy(sig[:32], r[:])
	copy(sig[32:64], s[:])
	for recid := byte(0); recid < 2; recid++ {
		sig[64] = recid
		recovered, err := crypto.Ecrecover(hash[:], sig)
		if err == nil && bytes.Equal(recovered, target) {
			return sig, nil
		}
	}
	return nil, errors.New("evm: signature does not match public key")
}

// ERC20TransferData returns the calldata of transfer(to, amount).
func ERC20TransferData(to common.Address, amount *big.Int) ([]byte, error) {
	if amount == nil || amount.Sign() < 0 || amount.BitLen() > 256 {
		return nil, errors.New("evm: amount must be a non-negative 256-bit integer")
	}
	data := make([]byte, 4+32+32)
	copy(data[:4], erc20TransferSelector)
	copy(data[4+12:36], to.Bytes())
	amount.FillBytes(data[36:])
	return data, nil
}

// HexHash returns hash as a 0x-prefixed hex string.
func HexHash(hash [32]byte) string {
	return hexutil.Encode(hash[:])
}
