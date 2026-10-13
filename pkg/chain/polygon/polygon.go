package polygon

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/didenkolab/mpc-sdk/pkg/chain/evm"
)

// Polygon network parameters
var (
	// Mainnet Chain ID: 137
	PolygonMainnetChainID = big.NewInt(137)
	// Testnet Chain ID: 80001 (Mumbai)
	PolygonTestnetChainID = big.NewInt(80001)
)

// ERC20 Token addresses on Polygon
var (
	USDCAddress = common.HexToAddress("0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174") // USDC
	USDTAddress = common.HexToAddress("0xc2132D05D31c914a87C6611C10748AEb04B58e8F") // USDT
	DAIAddress  = common.HexToAddress("0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063") // DAI
	WETHAddress = common.HexToAddress("0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619") // WETH
	WBTCAddress = common.HexToAddress("0x1bfd67037b42cf73acf2047067bd4f2c47d9bfd6") // WBTC
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

// DeriveAddress creates Polygon address from compressed secp256k1 pubkey.
// Polygon uses the same address format as Ethereum.
func DeriveAddress(compressedPub []byte) (common.Address, error) {
	return evm.DeriveAddress(compressedPub)
}

// BuildLegacyTx creates a legacy transaction for Polygon network.
func BuildLegacyTx(in LegacyTxInput) (*types.Transaction, types.Signer, [32]byte, error) {
	if in.ChainID == nil {
		in.ChainID = PolygonMainnetChainID
	}

	to, err := evm.ParseAddress(in.To)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	tx := types.NewTransaction(in.Nonce, to, in.Value, in.GasLimit, in.GasPrice, in.Data)
	signer := types.NewEIP155Signer(in.ChainID)
	h := signer.Hash(tx)
	var hash [32]byte
	copy(hash[:], h.Bytes())
	return tx, signer, hash, nil
}

// BuildEIP1559Tx creates an EIP-1559 transaction for Polygon network.
func BuildEIP1559Tx(in EIP1559TxInput) (*types.Transaction, types.Signer, [32]byte, error) {
	if in.ChainID == nil {
		in.ChainID = PolygonMainnetChainID
	}

	to, err := evm.ParseAddress(in.To)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}

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

// BuildMATICTransfer creates a MATIC transfer transaction.
func BuildMATICTransfer(from common.Address, to string, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	chainID := PolygonMainnetChainID
	if !isMainnet {
		chainID = PolygonTestnetChainID
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

// BuildERC20Transfer creates an ERC20 token transfer transaction.
func BuildERC20Transfer(tokenAddress common.Address, to common.Address, amount *big.Int,
	nonce uint64, gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	chainID := PolygonMainnetChainID
	if !isMainnet {
		chainID = PolygonTestnetChainID
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
		Value:    big.NewInt(0), // No MATIC sent for ERC20 transfer
		Data:     data,
		ChainID:  chainID,
	}

	return BuildLegacyTx(input)
}

// BuildUSDCTransfer creates a USDC transfer transaction on Polygon.
func BuildUSDCTransfer(to common.Address, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	var tokenAddr common.Address
	if isMainnet {
		tokenAddr = USDCAddress
	} else {
		// Testnet USDC address (example)
		tokenAddr = common.HexToAddress("0x742d35cc6635c0532925a3b8bc0c8ce47a9e4a8e")
	}

	return BuildERC20Transfer(tokenAddr, to, amount, nonce, gasPrice, gasLimit, isMainnet)
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

// GetGasPrice returns recommended gas price for Polygon network.
func GetGasPrice(isMainnet bool) *big.Int {
	if isMainnet {
		return big.NewInt(30000000000) // 30 gwei (typical for Polygon mainnet)
	}
	return big.NewInt(1000000000) // 1 gwei (testnet)
}

// GetChainID returns the chain ID for the network.
func GetChainID(isMainnet bool) *big.Int {
	if isMainnet {
		return PolygonMainnetChainID
	}
	return PolygonTestnetChainID
}
