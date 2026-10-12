package arbitrum

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/didenkolab/mpc-sdk/pkg/chain/evm"
)

// Arbitrum network parameters
var (
	// Mainnet Chain ID: 42161
	ArbitrumMainnetChainID = big.NewInt(42161)
	// Testnet Chain ID: 421614 (Arbitrum Sepolia)
	ArbitrumTestnetChainID = big.NewInt(421614)
)

// ERC20 Token addresses on Arbitrum One
var (
	USDCAddress = common.HexToAddress("0xaf88d065e77c8cC2239327C5EDb3A432268e5831") // USDC native
	USDTAddress = common.HexToAddress("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9") // USDT
	ARBAddress  = common.HexToAddress("0x912CE59144191C1204E64559FE8253a0e49E6548") // ARB token
	WETHAddress = common.HexToAddress("0x82aF49447D8a07e3bd95BD0d56f35241523fBab1") // WETH
	WBTCAddress = common.HexToAddress("0x2f2a2543B76A4166549F7aaB2e75Bef0aefC5B0f") // WBTC
	GMXAddress  = common.HexToAddress("0xfc5A1A6EB076a2C7aD06eD22C90d7E710E35ad0a") // GMX
	DAIAddress  = common.HexToAddress("0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1") // DAI
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

// DeriveAddress creates Arbitrum address from compressed secp256k1 pubkey.
// Arbitrum uses the same address format as Ethereum.
func DeriveAddress(compressedPub []byte) (common.Address, error) {
	return evm.DeriveAddress(compressedPub)
}

// BuildLegacyTx creates a legacy transaction for Arbitrum network.
func BuildLegacyTx(in LegacyTxInput) (*types.Transaction, types.Signer, [32]byte, error) {
	if in.ChainID == nil {
		in.ChainID = ArbitrumMainnetChainID
	}

	to := common.HexToAddress(in.To)
	tx := types.NewTransaction(in.Nonce, to, in.Value, in.GasLimit, in.GasPrice, in.Data)
	signer := types.NewEIP155Signer(in.ChainID)
	h := signer.Hash(tx)
	var hash [32]byte
	copy(hash[:], h.Bytes())
	return tx, signer, hash, nil
}

// BuildEIP1559Tx creates an EIP-1559 transaction for Arbitrum network.
func BuildEIP1559Tx(in EIP1559TxInput) (*types.Transaction, types.Signer, [32]byte, error) {
	if in.ChainID == nil {
		in.ChainID = ArbitrumMainnetChainID
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

// BuildETHTransfer creates an ETH transfer transaction on Arbitrum.
func BuildETHTransfer(from common.Address, to string, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	chainID := ArbitrumMainnetChainID
	if !isMainnet {
		chainID = ArbitrumTestnetChainID
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

	chainID := ArbitrumMainnetChainID
	if !isMainnet {
		chainID = ArbitrumTestnetChainID
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
		Value:    big.NewInt(0), // No ETH sent for ERC20 transfer
		Data:     data,
		ChainID:  chainID,
	}

	return BuildLegacyTx(input)
}

// BuildUSDCTransfer creates a USDC transfer transaction on Arbitrum.
func BuildUSDCTransfer(to common.Address, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	var tokenAddr common.Address
	if isMainnet {
		tokenAddr = USDCAddress
	} else {
		// Testnet USDC address (example)
		tokenAddr = common.HexToAddress("0x75faf114eafb1bdbe2f0316df893fd58ce46aa4d")
	}

	return BuildERC20Transfer(tokenAddr, to, amount, nonce, gasPrice, gasLimit, isMainnet)
}

// BuildUSDTTransfer creates a USDT transfer transaction on Arbitrum.
func BuildUSDTTransfer(to common.Address, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	var tokenAddr common.Address
	if isMainnet {
		tokenAddr = USDTAddress
	} else {
		// Testnet USDT address (example)
		tokenAddr = common.HexToAddress("0xfd064A18f3BF249cf1f87FC203E90D8f650f2d63")
	}

	return BuildERC20Transfer(tokenAddr, to, amount, nonce, gasPrice, gasLimit, isMainnet)
}

// BuildARBTransfer creates an ARB token transfer transaction.
func BuildARBTransfer(to common.Address, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	var tokenAddr common.Address
	if isMainnet {
		tokenAddr = ARBAddress
	} else {
		// Testnet ARB address (example)
		tokenAddr = common.HexToAddress("0x2416092f143378750bb29b79eD961ab195CcEea5")
	}

	return BuildERC20Transfer(tokenAddr, to, amount, nonce, gasPrice, gasLimit, isMainnet)
}

// BuildGMXTransfer creates a GMX token transfer transaction.
func BuildGMXTransfer(to common.Address, amount *big.Int, nonce uint64,
	gasPrice *big.Int, gasLimit uint64, isMainnet bool) (*types.Transaction, types.Signer, [32]byte, error) {

	var tokenAddr common.Address
	if isMainnet {
		tokenAddr = GMXAddress
	} else {
		// Testnet GMX address (example)
		tokenAddr = common.HexToAddress("0x8d9ba570D6cb60C7e3e0F31343Efe75AB8E65FB1")
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

// GetGasPrice returns recommended gas price for Arbitrum network.
func GetGasPrice(isMainnet bool) *big.Int {
	if isMainnet {
		return big.NewInt(100000000) // 0.1 gwei (very low fees on Arbitrum)
	}
	return big.NewInt(100000000) // 0.1 gwei (testnet)
}

// GetChainID returns the chain ID for the network.
func GetChainID(isMainnet bool) *big.Int {
	if isMainnet {
		return ArbitrumMainnetChainID
	}
	return ArbitrumTestnetChainID
}
