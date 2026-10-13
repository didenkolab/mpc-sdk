package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/didenkolab/mpc-sdk/examples/internal/mpcdemo"
	"github.com/didenkolab/mpc-sdk/pkg/chain/evm"
)

// ethDefaultRPC is a public, keyless Sepolia endpoint. Override with -rpc or
// SEPOLIA_RPC_URL.
const ethDefaultRPC = "https://ethereum-sepolia-rpc.publicnode.com"

type evmTestnet struct {
	name     string
	explorer string
	faucets  []string
}

// evmTestnets is an allowlist: any other chain ID (mainnet included) is refused.
var evmTestnets = map[uint64]evmTestnet{
	11155111: {"Sepolia", "https://sepolia.etherscan.io/tx/", []string{
		"https://cloud.google.com/application/web3/faucet/ethereum/sepolia",
		"https://sepolia-faucet.pk910.de (PoW faucet, no account needed)",
		"https://www.alchemy.com/faucets/ethereum-sepolia",
	}},
	560048: {"Hoodi", "https://hoodi.etherscan.io/tx/", []string{"https://hoodi-faucet.pk910.de"}},
}

const (
	ethDefaultAmount = 10_000_000_000_000 // 0.00001 ETH in wei
	ethTransferGas   = 21_000
)

func runEthereum(keyshares []string, o options) error {
	url := o.rpc
	if url == "" {
		url = os.Getenv("SEPOLIA_RPC_URL")
	}
	if url == "" {
		url = ethDefaultRPC
	}

	pub, err := mpcdemo.DKLS23PublicKey(keyshares[0])
	if err != nil {
		return err
	}
	from, err := evm.DeriveAddress(pub)
	if err != nil {
		return err
	}
	mpcdemo.Step(2, "Threshold address")
	mpcdemo.Field("public key", hex.EncodeToString(pub))
	mpcdemo.Field("address", from.Hex())

	mpcdemo.Step(3, "Network check")
	var chainIDHex hexutil.Big
	if err := jsonRPC(url, "eth_chainId", []any{}, &chainIDHex); err != nil {
		return err
	}
	chainID := (*big.Int)(&chainIDHex)
	net, ok := evmTestnet{}, false
	if chainID.IsUint64() {
		net, ok = evmTestnets[chainID.Uint64()]
	}
	if !ok {
		return fmt.Errorf("%s reports chain ID %s, which is not an allowed test network (mainnet is 1); refusing", url, chainID)
	}
	mpcdemo.Field("RPC", url)
	mpcdemo.Field("network", fmt.Sprintf("%s (chain ID %s)", net.name, chainID))

	to := from
	if o.to != "" {
		if !common.IsHexAddress(o.to) {
			return fmt.Errorf("-to %q is not an EVM address", o.to)
		}
		to = common.HexToAddress(o.to)
	}
	value, err := amountOr(o.amount, big.NewInt(ethDefaultAmount))
	if err != nil {
		return err
	}

	mpcdemo.Step(4, "Chain data")
	var balance, gasPrice hexutil.Big
	var nonce hexutil.Uint64
	var code hexutil.Bytes
	if err := jsonRPC(url, "eth_getBalance", []any{from, "latest"}, &balance); err != nil {
		return err
	}
	if err := jsonRPC(url, "eth_getTransactionCount", []any{from, "pending"}, &nonce); err != nil {
		return err
	}
	if err := jsonRPC(url, "eth_gasPrice", []any{}, &gasPrice); err != nil {
		return err
	}
	if err := jsonRPC(url, "eth_getCode", []any{to, "latest"}, &code); err != nil {
		return err
	}
	if len(code) > 0 {
		return fmt.Errorf("-to %s is a contract; this example only sends plain 21000-gas transfers", to.Hex())
	}
	// Pay 25% above the current price so the transaction is not stuck.
	price := new(big.Int).Div(new(big.Int).Mul(gasPrice.ToInt(), big.NewInt(125)), big.NewInt(100))
	cost := new(big.Int).Add(value, new(big.Int).Mul(price, big.NewInt(ethTransferGas)))
	mpcdemo.Field("balance", fmt.Sprintf("%s wei", balance.ToInt()))
	mpcdemo.Field("nonce", uint64(nonce))
	mpcdemo.Field("gas price", fmt.Sprintf("%s wei (node: %s)", price, gasPrice.ToInt()))
	if balance.ToInt().Cmp(cost) < 0 {
		if !o.assumeFunded {
			return faucetHint(from.Hex(), append(net.faucets,
				fmt.Sprintf("you need at least %s wei; funds are usable after ~1 block (12 s)", cost))...)
		}
		mpcdemo.Field("ASSUMED BALANCE", "address is unfunded (-assume-funded); the node would reject this transaction")
	}

	mpcdemo.Step(5, "Unsigned transaction")
	tx, signer, hash, err := evm.BuildUnsigned(evm.LegacyTxInput{
		Nonce: uint64(nonce), GasPrice: price, GasLimit: ethTransferGas,
		To: to.Hex(), Value: value, ChainID: chainID,
	})
	if err != nil {
		return err
	}
	mpcdemo.Field("to", fmt.Sprintf("%s (%s wei)", to.Hex(), value))
	mpcdemo.Field("EIP-155 hash", hex.EncodeToString(hash[:]))

	mpcdemo.Step(6, "Threshold signing (parties 1 and 3)")
	sig, err := mpcdemo.DKLS23Sign(signers(keyshares), hash)
	if err != nil {
		return err
	}
	sig65, err := evm.BuildSignature65(hash, pub, hex.EncodeToString(sig))
	if err != nil {
		return err
	}
	signed, err := evm.AssembleSignature(tx, signer, sig65)
	if err != nil {
		return err
	}
	mpcdemo.Field("signature", hex.EncodeToString(sig65))

	mpcdemo.Step(7, "Local verification and signed transaction")
	sender, err := types.Sender(signer, signed)
	if err != nil {
		return fmt.Errorf("recover sender: %w", err)
	}
	if sender != from {
		return fmt.Errorf("signature recovers to %s, want %s", sender.Hex(), from.Hex())
	}
	mpcdemo.Field("recovered sender", sender.Hex()+" (matches)")
	raw, err := signed.MarshalBinary()
	if err != nil {
		return err
	}
	mpcdemo.Field("tx hash", signed.Hash().Hex())
	return finish(o, "raw tx", hexutil.Encode(raw), func() (string, error) {
		var id common.Hash
		err := jsonRPC(url, "eth_sendRawTransaction", []any{hexutil.Encode(raw)}, &id)
		return id.Hex(), err
	}, func(id string) string { return net.explorer + id })
}
