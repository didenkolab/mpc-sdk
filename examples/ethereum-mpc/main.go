// Command ethereum-mpc creates a 2-of-2 DKLs23 key, derives its EVM address
// and signs EIP-155 transactions with the threshold protocol: an ETH transfer,
// an ERC-20 transfer, and the same native transfer on several EVM chains. The
// same key and address work on every EVM chain; only the chain ID differs.
//
// Each signed transaction is verified by recovering the sender with
// go-ethereum and comparing it to the MPC address. Nonces and gas prices are
// fixed demo values, so the transactions are not meant to be broadcast as-is.
package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/evm"
)

const recipient = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

// usdc is the USDC token contract on Ethereum mainnet.
const usdc = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

var gwei = big.NewInt(1_000_000_000)

func main() {
	mpcdemo.Run("Ethereum and EVM chains: DKLs23 2-of-2, EIP-155 transactions", run)
}

func run() error {
	mpcdemo.Step(1, "Distributed key generation")
	keyshares, err := mpcdemo.DKLS23Keygen(2, 2, nil)
	if err != nil {
		return err
	}
	pub, err := mpcdemo.DKLS23PublicKey(keyshares[0])
	if err != nil {
		return err
	}
	mpcdemo.Field("public key", hex.EncodeToString(pub))

	mpcdemo.Step(2, "Address")
	addr, err := evm.DeriveAddress(pub)
	if err != nil {
		return err
	}
	mpcdemo.Field("EVM address", addr.Hex())

	mpcdemo.Step(3, "Ethereum mainnet: ETH and ERC-20 transfers")
	ethValue := new(big.Int).Mul(big.NewInt(1_000_000_000), gwei) // 1 ETH
	ethTx, err := signTx(keyshares, pub, addr, evm.LegacyTxInput{
		Nonce: 0, GasPrice: new(big.Int).Mul(big.NewInt(20), gwei), GasLimit: 21_000,
		To: recipient, Value: ethValue, ChainID: big.NewInt(1),
	})
	if err != nil {
		return fmt.Errorf("ETH transfer: %w", err)
	}
	if err := printTx("ETH transfer", ethTx); err != nil {
		return err
	}

	data, err := evm.ERC20TransferData(common.HexToAddress(recipient), big.NewInt(1_000_000)) // 1 USDC
	if err != nil {
		return err
	}
	erc20Tx, err := signTx(keyshares, pub, addr, evm.LegacyTxInput{
		Nonce: 1, GasPrice: new(big.Int).Mul(big.NewInt(20), gwei), GasLimit: 60_000,
		To: usdc, Value: big.NewInt(0), Data: data, ChainID: big.NewInt(1),
	})
	if err != nil {
		return fmt.Errorf("ERC-20 transfer: %w", err)
	}
	if err := printTx("USDC transfer", erc20Tx); err != nil {
		return err
	}

	mpcdemo.Step(4, "Same key on other EVM chains")
	chains := []struct {
		name     string
		chainID  int64
		gasPrice int64 // in gwei
	}{
		{"BSC", 56, 5},
		{"Polygon", 137, 30},
		{"Arbitrum", 42161, 1},
		{"Avalanche", 43114, 25},
	}
	for _, c := range chains {
		tx, err := signTx(keyshares, pub, addr, evm.LegacyTxInput{
			Nonce: 0, GasPrice: new(big.Int).Mul(big.NewInt(c.gasPrice), gwei), GasLimit: 21_000,
			To: recipient, Value: ethValue, ChainID: big.NewInt(c.chainID),
		})
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		mpcdemo.Field(fmt.Sprintf("%s (%d)", c.name, c.chainID), tx.Hash().Hex())
	}

	mpcdemo.Done("every transaction recovers to the MPC address")
	return nil
}

// signTx builds an EIP-155 transaction, signs its hash with the threshold
// protocol, attaches the signature and checks that the recovered sender is
// the MPC address.
func signTx(keyshares []string, pub []byte, from common.Address, in evm.LegacyTxInput) (*types.Transaction, error) {
	tx, signer, hash, err := evm.BuildUnsigned(in)
	if err != nil {
		return nil, err
	}
	sig, err := mpcdemo.DKLS23Sign(keyshares, hash)
	if err != nil {
		return nil, err
	}
	// Threshold ECDSA yields r||s; the recovery ID is found by trial and S is
	// normalized to the lower half as Ethereum requires.
	sig65, err := evm.BuildSignature65(hash, pub, hex.EncodeToString(sig))
	if err != nil {
		return nil, err
	}
	signed, err := evm.AssembleSignature(tx, signer, sig65)
	if err != nil {
		return nil, err
	}
	sender, err := types.Sender(signer, signed)
	if err != nil {
		return nil, fmt.Errorf("recover sender: %w", err)
	}
	if sender != from {
		return nil, fmt.Errorf("recovered sender %s, want %s", sender.Hex(), from.Hex())
	}
	return signed, nil
}

func printTx(label string, tx *types.Transaction) error {
	raw, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	mpcdemo.Field(label+" hash", tx.Hash().Hex())
	mpcdemo.Field(label+" raw", "0x"+hex.EncodeToString(raw))
	return nil
}
