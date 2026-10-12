package bsc

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/didenkolab/mpc-sdk/pkg/chain/evm"
)

// BSC network parameters
var (
	// Mainnet Chain ID: 56
	BSCMainnetChainID = big.NewInt(56)
	// Testnet Chain ID: 97
	BSCTestnetChainID = big.NewInt(97)
)

// BEP20 Token addresses on BSC
var (
	USDTAddress = common.HexToAddress("0x55d398326f99059ff775485246999027b3197955") // USDT
	BUSDAddress = common.HexToAddress("0xe9e7cea3dedca5984780bafc599bd69add087d56") // BUSD
	CAKEAddress = common.HexToAddress("0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82") // PancakeSwap
	WBNBAddress = common.HexToAddress("0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c") // Wrapped BNB
	ETHAddress  = common.HexToAddress("0x2170ed0880ac9a755fd29b2688956bd959f933f8") // Ethereum Token
)

// LegacyTxInput represents input for legacy transaction
type LegacyTxInput struct {
	Nonce    uint64
	GasPrice *big.Int
	GasLimit uint64
	To       string
	Value    *big.Int
	Data     []byte
	ChainID  *big.Int
}

// EIP1559TxInput represents input for EIP-1559 transaction
type EIP1559TxInput struct {
	Nonce                uint64
	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
	GasLimit             uint64
	To                   string
	Value                *big.Int
	Data                 []byte
	ChainID              *big.Int
}

// DeriveAddress creates BSC address from compressed secp256k1 pubkey.
// BSC uses the same address format as Ethereum.
func DeriveAddress(compressedPub []byte) (common.Address, error) {
	return evm.DeriveAddress(compressedPub)
}

// BuildLegacyTx creates a legacy transaction for BSC network.
func BuildLegacyTx(in LegacyTxInput) (*types.Transaction, types.Signer, [32]byte, error) {
	if in.ChainID == nil {
		in.ChainID = BSCMainnetChainID
	}

	to := common.HexToAddress(in.To)
	tx := types.NewTransaction(in.Nonce, to, in.Value, in.GasLimit, in.GasPrice, in.Data)
	signer := types.NewEIP155Signer(in.ChainID)
	h := signer.Hash(tx)
	var hash [32]byte
	copy(hash[:], h.Bytes())
	return tx, signer, hash, nil
}

// BuildEIP1559Tx creates an EIP-1559 transaction for BSC network.
func BuildEIP1559Tx(in EIP1559TxInput) (*types.Transaction, types.Signer, [32]byte, error) {
	if in.ChainID == nil {
		in.ChainID = BSCMainnetChainID
	}

	to := common.HexToAddress(in.To)

	dynamicTx := &types.DynamicFeeTx{
		ChainID:   in.ChainID,
		Nonce:     in.Nonce,
		GasTipCap: in.MaxPriorityFeePerGas,
		GasFeeCap: in.MaxFeePerGas,
		Gas:       in.GasLimit,
		To:        &to,
		Value:     in.Value,
		Data:      in.Data,
	}

	tx := types.NewTx(dynamicTx)
	signer := types.NewLondonSigner(in.ChainID)
	h := signer.Hash(tx)
	var hash [32]byte
	copy(hash[:], h.Bytes())
	return tx, signer, hash, nil
}

// BuildBNBTransfer creates a BNB transfer transaction.
func BuildBNBTransfer(from common.Address, to string, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	chainID := BSCMainnetChainID
	if !isMainnet {
		chainID = BSCTestnetChainID
	}

	input := LegacyTxInput{
		Nonce:    nonce,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		To:       to,
		Value:    amount,
		Data:     nil,
		ChainID:  chainID,
	}

	return BuildLegacyTx(input)
}

// BuildBEP20Transfer creates a BEP20 token transfer transaction.
func BuildBEP20Transfer(tokenAddress common.Address, to common.Address, amount *big.Int,
	nonce uint64, gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	chainID := BSCMainnetChainID
	if !isMainnet {
		chainID = BSCTestnetChainID
	}

	data, err := evm.ERC20TransferData(to, amount)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

	input := LegacyTxInput{
		Nonce:    nonce,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		To:       tokenAddress.Hex(),
		Value:    big.NewInt(0), // No BNB sent for BEP20 transfer
		Data:     data,
		ChainID:  chainID,
	}

	return BuildLegacyTx(input)
}

// BuildUSDTTransfer creates a USDT transfer transaction on BSC.
func BuildUSDTTransfer(to common.Address, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	var tokenAddr common.Address
	if isMainnet {
		tokenAddr = USDTAddress
	} else {
		// Testnet USDT address (example)
		tokenAddr = common.HexToAddress("0x7ef95a0fee0dd31b22626fa2e10ee6a223f8a684")
	}

	return BuildBEP20Transfer(tokenAddr, to, amount, nonce, gasPrice, gasLimit, isMainnet)
}

// BuildBUSDTransfer creates a BUSD transfer transaction on BSC.
func BuildBUSDTransfer(to common.Address, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	var tokenAddr common.Address
	if isMainnet {
		tokenAddr = BUSDAddress
	} else {
		// Testnet BUSD address (example)
		tokenAddr = common.HexToAddress("0xed24fc36d5ee211ea25a80239fb8c4cfd80f12ee")
	}

	return BuildBEP20Transfer(tokenAddr, to, amount, nonce, gasPrice, gasLimit, isMainnet)
}

// AttachSignature attaches a signature to the transaction.
func AttachSignature(tx *types.Transaction, signer types.Signer, sig []byte) (*types.Transaction, error) {
	if len(sig) != 65 {
		return nil, errors.New("signature must be 65 bytes")
	}
	return tx.WithSignature(signer, sig)
}

// BuildSignature65 converts a hex r||s threshold signature into the 65-byte
// R|S|V form expected by AttachSignature. See evm.BuildSignature65.
func BuildSignature65(hash [32]byte, compressedPub []byte, sigHex string) ([]byte, error) {
	return evm.BuildSignature65(hash, compressedPub, sigHex)
}

// GetGasPrice returns recommended gas price for BSC network.
func GetGasPrice(isMainnet bool) *big.Int {
	if isMainnet {
		return big.NewInt(5000000000) // 5 gwei (typical for BSC mainnet)
	}
	return big.NewInt(10000000000) // 10 gwei (testnet)
}

// GetChainID returns the chain ID for the network.
func GetChainID(isMainnet bool) *big.Int {
	if isMainnet {
		return BSCMainnetChainID
	}
	return BSCTestnetChainID
}
