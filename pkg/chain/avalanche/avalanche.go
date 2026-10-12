package avalanche

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// Avalanche C-Chain network parameters
const (
	// Mainnet (C-Chain)
	AvalancheMainnetChainID = 43114
	// Testnet Fuji (C-Chain)
	AvalancheTestnetChainID = 43113
)

// Gas prices for Avalanche C-Chain (much lower than Ethereum mainnet)
const (
	// Standard gas price in Gwei (very low fees on Avalanche)
	DefaultGasPrice = 25000000000 // 25 gwei
	// Fast transaction gas price
	FastGasPrice = 35000000000 // 35 gwei
	// Instant transaction gas price
	InstantGasPrice = 50000000000 // 50 gwei
)

// Gas limits for different operations
const (
	StandardTransferGas = 21000  // Standard ETH transfer
	TokenTransferGas    = 65000  // ERC20 token transfer
	ContractCallGas     = 100000 // Smart contract interaction
)

// Common Avalanche C-Chain tokens
var (
	// AVAX native token (no contract address needed)
	AVAXNativeToken = common.HexToAddress("0x0000000000000000000000000000000000000000")

	// Wrapped AVAX
	WAVAXToken = common.HexToAddress("0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7")

	// Major stablecoins on Avalanche
	USDCToken = common.HexToAddress("0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E") // USDC
	USDTToken = common.HexToAddress("0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7") // USDT
	DAIToken  = common.HexToAddress("0xd586E7F844cEa2F87f50152665BCbc2C279D8d70") // DAI
	MIMToken  = common.HexToAddress("0x130966628846BFd36ff31a822705796e8cb8C18D") // MIM

	// DeFi tokens
	JOEToken   = common.HexToAddress("0x6e84a6216eA6dACC71eE8E6b0a5B7322EEbC0fDd") // JOE (TraderJoe)
	PNGToken   = common.HexToAddress("0x60781C2586D68229fde47564546784ab3fACA982") // PNG (Pangolin)
	QIToken    = common.HexToAddress("0x8729438EB15e2C8B576fCc6AeCdA6A148776C0F5") // QI (BENQI)
	AVAXSToken = common.HexToAddress("0x2b2C81e08f1Af8835f25DaF6E00B7f22D8b007B4") // sAVAX (Staked AVAX)

	// Bridged assets
	WETHToken = common.HexToAddress("0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB") // WETH.e (Bridged Ethereum)
	WBTCToken = common.HexToAddress("0x50b7545627a5162F82A992c33b87aDc75187B218") // WBTC.e (Bridged Bitcoin)
	LINKToken = common.HexToAddress("0x5947BB275c521040051D82396192181b413227A3") // LINK.e (Bridged Chainlink)
)

// DeriveAddress creates Avalanche C-Chain address from compressed ECDSA public key.
// Returns standard Ethereum-style 0x... address.
func DeriveAddress(compressedPub []byte) (common.Address, error) {
	if len(compressedPub) != 33 {
		return common.Address{}, errors.New("compressed pubkey must be 33 bytes")
	}

	// Decompress the public key
	pk, err := crypto.DecompressPubkey(compressedPub)
	if err != nil {
		return common.Address{}, err
	}

	// Generate Ethereum-style address
	address := crypto.PubkeyToAddress(*pk)
	return address, nil
}

// BuildAVAXTransfer creates native AVAX transfer transaction.
// amount is in wei (1 AVAX = 10^18 wei)
func BuildAVAXTransfer(fromPrivKey *ecdsa.PrivateKey, to common.Address, amount *big.Int,
	nonce uint64, isTestnet bool) (*types.Transaction, []byte, error) {

	chainID := AvalancheMainnetChainID
	if isTestnet {
		chainID = AvalancheTestnetChainID
	}

	// Create transaction
	tx := types.NewTransaction(
		nonce,
		to,
		amount,
		StandardTransferGas,
		big.NewInt(DefaultGasPrice),
		nil, // No data for simple transfer
	)

	// Create signer for Avalanche C-Chain
	signer := types.NewEIP155Signer(big.NewInt(int64(chainID)))

	// Get transaction hash for signing
	txHash := signer.Hash(tx)

	return tx, txHash.Bytes(), nil
}

// BuildERC20Transfer creates ERC20 token transfer transaction on Avalanche C-Chain.
func BuildERC20Transfer(fromPrivKey *ecdsa.PrivateKey, tokenContract, to common.Address,
	amount *big.Int, nonce uint64, isTestnet bool) (*types.Transaction, []byte, error) {

	chainID := AvalancheMainnetChainID
	if isTestnet {
		chainID = AvalancheTestnetChainID
	}

	// ERC20 transfer function signature: transfer(address,uint256)
	// Function selector: 0xa9059cbb
	data := make([]byte, 68)
	copy(data[0:4], []byte{0xa9, 0x05, 0x9c, 0xbb}) // transfer function selector

	// Encode recipient address (32 bytes, padded)
	copy(data[16:36], to.Bytes())

	// Encode amount (32 bytes, big endian)
	amountBytes := amount.Bytes()
	copy(data[68-len(amountBytes):68], amountBytes)

	// Create transaction to token contract
	tx := types.NewTransaction(
		nonce,
		tokenContract,
		big.NewInt(0), // No AVAX value for token transfer
		TokenTransferGas,
		big.NewInt(DefaultGasPrice),
		data,
	)

	// Create signer
	signer := types.NewEIP155Signer(big.NewInt(int64(chainID)))
	txHash := signer.Hash(tx)

	return tx, txHash.Bytes(), nil
}

// BuildUSDCTransfer creates USDC transfer transaction (6 decimals).
func BuildUSDCTransfer(fromPrivKey *ecdsa.PrivateKey, to common.Address, amount *big.Int,
	nonce uint64, isTestnet bool) (*types.Transaction, []byte, error) {

	return BuildERC20Transfer(fromPrivKey, USDCToken, to, amount, nonce, isTestnet)
}

// BuildJOETransfer creates JOE token transfer transaction (18 decimals).
func BuildJOETransfer(fromPrivKey *ecdsa.PrivateKey, to common.Address, amount *big.Int,
	nonce uint64, isTestnet bool) (*types.Transaction, []byte, error) {

	return BuildERC20Transfer(fromPrivKey, JOEToken, to, amount, nonce, isTestnet)
}

// BuildEIP1559Tx creates EIP-1559 transaction with dynamic fees for Avalanche C-Chain.
func BuildEIP1559Tx(to common.Address, amount *big.Int, data []byte, nonce uint64,
	gasLimit uint64, maxFeePerGas, maxPriorityFeePerGas *big.Int, isTestnet bool) (*types.Transaction, []byte, error) {

	chainID := AvalancheMainnetChainID
	if isTestnet {
		chainID = AvalancheTestnetChainID
	}

	// Create EIP-1559 transaction
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(int64(chainID)),
		Nonce:     nonce,
		GasTipCap: maxPriorityFeePerGas,
		GasFeeCap: maxFeePerGas,
		Gas:       gasLimit,
		To:        &to,
		Value:     amount,
		Data:      data,
	})

	// Create London signer for EIP-1559
	signer := types.NewLondonSigner(big.NewInt(int64(chainID)))
	txHash := signer.Hash(tx)

	return tx, txHash.Bytes(), nil
}

// AttachSignature attaches ECDSA signature to Avalanche C-Chain transaction.
func AttachSignature(tx *types.Transaction, signature []byte, isTestnet bool) (*types.Transaction, error) {
	if len(signature) != 65 {
		return nil, errors.New("signature must be 65 bytes")
	}

	chainID := AvalancheMainnetChainID
	if isTestnet {
		chainID = AvalancheTestnetChainID
	}

	// Choose appropriate signer based on transaction type
	var signer types.Signer
	if tx.Type() == types.DynamicFeeTxType {
		signer = types.NewLondonSigner(big.NewInt(int64(chainID)))
	} else {
		signer = types.NewEIP155Signer(big.NewInt(int64(chainID)))
	}

	// Sign transaction with provided signature
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		return nil, err
	}

	return signedTx, nil
}

// GetChainConfig returns Avalanche C-Chain configuration.
func GetChainConfig(isTestnet bool) *params.ChainConfig {
	if isTestnet {
		return &params.ChainConfig{
			ChainID:             big.NewInt(AvalancheTestnetChainID),
			HomesteadBlock:      big.NewInt(0),
			DAOForkBlock:        nil,
			DAOForkSupport:      false,
			EIP150Block:         big.NewInt(0),
			EIP155Block:         big.NewInt(0),
			EIP158Block:         big.NewInt(0),
			ByzantiumBlock:      big.NewInt(0),
			ConstantinopleBlock: big.NewInt(0),
			PetersburgBlock:     big.NewInt(0),
			IstanbulBlock:       big.NewInt(0),
			MuirGlacierBlock:    big.NewInt(0),
			BerlinBlock:         big.NewInt(0),
			LondonBlock:         big.NewInt(0), // EIP-1559 support
		}
	}

	return &params.ChainConfig{
		ChainID:             big.NewInt(AvalancheMainnetChainID),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        nil,
		DAOForkSupport:      false,
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0), // EIP-1559 support
	}
}

// ConvertAVAXToWei converts AVAX to wei (1 AVAX = 10^18 wei)
func ConvertAVAXToWei(avax float64) *big.Int {
	avaxBig := big.NewFloat(avax)
	weiBig := new(big.Float).Mul(avaxBig, big.NewFloat(1e18))

	result := new(big.Int)
	weiBig.Int(result)
	return result
}

// ConvertWeiToAVAX converts wei to AVAX
func ConvertWeiToAVAX(wei *big.Int) float64 {
	weiBig := new(big.Float).SetInt(wei)
	avaxBig := new(big.Float).Quo(weiBig, big.NewFloat(1e18))

	result, _ := avaxBig.Float64()
	return result
}

// ConvertUSDCToBaseUnits converts USDC to base units (6 decimals)
func ConvertUSDCToBaseUnits(usdc float64) *big.Int {
	usdcBig := big.NewFloat(usdc)
	baseUnitsBig := new(big.Float).Mul(usdcBig, big.NewFloat(1e6))

	result := new(big.Int)
	baseUnitsBig.Int(result)
	return result
}

// ConvertBaseUnitsToUSDC converts USDC base units to USDC (6 decimals)
func ConvertBaseUnitsToUSDC(baseUnits *big.Int) float64 {
	baseUnitsBig := new(big.Float).SetInt(baseUnits)
	usdcBig := new(big.Float).Quo(baseUnitsBig, big.NewFloat(1e6))

	result, _ := usdcBig.Float64()
	return result
}

// GetDefaultGasPrice returns recommended gas price for Avalanche C-Chain
func GetDefaultGasPrice(priority string) *big.Int {
	switch priority {
	case "slow":
		return big.NewInt(DefaultGasPrice)
	case "fast":
		return big.NewInt(FastGasPrice)
	case "instant":
		return big.NewInt(InstantGasPrice)
	default:
		return big.NewInt(DefaultGasPrice)
	}
}

// GetTokenInfo returns information about common Avalanche tokens
func GetTokenInfo(tokenAddress common.Address) (name string, symbol string, decimals uint8) {
	switch tokenAddress {
	case USDCToken:
		return "USD Coin", "USDC", 6
	case USDTToken:
		return "Tether USD", "USDT", 6
	case DAIToken:
		return "Dai Stablecoin", "DAI", 18
	case JOEToken:
		return "JoeToken", "JOE", 18
	case PNGToken:
		return "Pangolin", "PNG", 18
	case WAVAXToken:
		return "Wrapped AVAX", "WAVAX", 18
	case WETHToken:
		return "Wrapped Ether", "WETH.e", 18
	case WBTCToken:
		return "Wrapped BTC", "WBTC.e", 8
	case LINKToken:
		return "ChainLink Token", "LINK.e", 18
	case QIToken:
		return "BENQI", "QI", 18
	case MIMToken:
		return "Magic Internet Money", "MIM", 18
	case AVAXSToken:
		return "Staked AVAX", "sAVAX", 18
	default:
		return "Unknown Token", "???", 18
	}
}

// IsValidAddress checks if an address is valid for Avalanche C-Chain
func IsValidAddress(address string) bool {
	return common.IsHexAddress(address)
}

// GetExplorerURL returns the block explorer URL for Avalanche
func GetExplorerURL(txHash string, isTestnet bool) string {
	if isTestnet {
		return "https://testnet.snowtrace.io/tx/" + txHash
	}
	return "https://snowtrace.io/tx/" + txHash
}
