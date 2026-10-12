package near

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
)

// NEAR network parameters
const (
	// NEAR Mainnet
	NEARMainnetChainID = "mainnet"
	// NEAR Testnet
	NEARTestnetChainID = "testnet"
)

// NEAR transaction action types
const (
	ActionTypeCreateAccount  = 0
	ActionTypeDeployContract = 1
	ActionTypeFunctionCall   = 2
	ActionTypeTransfer       = 3
	ActionTypeStake          = 4
	ActionTypeAddKey         = 5
	ActionTypeDeleteKey      = 6
	ActionTypeDeleteAccount  = 7
)

// Common NEAR token addresses and contracts
var (
	// NEAR native token (no contract address needed)
	NEARNativeToken = "NEAR"

	// Common NEAR tokens
	USDCContract = "a0b86991c431e56fd93ae47d9e9ac50e8b6a0c8c0f8f4b0d5f4f5b1e4e9d8c7b6" // Example
	USDTContract = "dac17f958d2ee523a2206206994597c13d831ec7f8f4b0d5f4f5b1e4e9d8c7b6"  // Example
	WETHContract = "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f8f4b0d5f4f5b1e4e9d8c7b6"  // Example
)

// NEARPublicKey represents a NEAR public key
type NEARPublicKey struct {
	KeyType uint8
	Data    []byte
}

// Transaction represents a NEAR transaction
type Transaction struct {
	SignerID   string
	PublicKey  NEARPublicKey
	Nonce      uint64
	ReceiverID string
	BlockHash  []byte
	Actions    []Action
}

// Action represents a transaction action
type Action struct {
	Type uint8
	Data interface{}
}

// TransferAction represents a NEAR transfer action
type TransferAction struct {
	Deposit *big.Int
}

// FunctionCallAction represents a function call action
type FunctionCallAction struct {
	MethodName string
	Args       []byte
	Gas        uint64
	Deposit    *big.Int
}

// StakeAction represents a staking action
type StakeAction struct {
	Stake     *big.Int
	PublicKey NEARPublicKey
}

// DeriveAddress creates NEAR address from Ed25519 public key.
// NEAR addresses are human-readable account IDs.
func DeriveAddress(ed25519PubKey []byte) (string, error) {
	if len(ed25519PubKey) != 32 {
		return "", errors.New("Ed25519 public key must be 32 bytes")
	}

	// NEAR addresses are derived from public keys using implicit accounts
	// For implicit accounts, the address is the hex representation of the public key
	return hex.EncodeToString(ed25519PubKey), nil
}

// DeriveImplicitAddress creates NEAR implicit account address
func DeriveImplicitAddress(ed25519PubKey []byte) (string, error) {
	if len(ed25519PubKey) != 32 {
		return "", errors.New("Ed25519 public key must be 32 bytes")
	}

	// Implicit account address is hex representation of public key
	return hex.EncodeToString(ed25519PubKey), nil
}

// DeriveNamedAddress creates a named NEAR account address
func DeriveNamedAddress(accountName string, isTestnet bool) (string, error) {
	if accountName == "" {
		return "", errors.New("account name cannot be empty")
	}

	if isTestnet {
		return accountName + ".testnet", nil
	}
	return accountName + ".near", nil
}

// BuildTransferTransaction creates a NEAR transfer transaction.
func BuildTransferTransaction(signerID, receiverID string, amount *big.Int, nonce uint64,
	blockHash []byte, publicKey []byte, isTestnet bool) (*Transaction, []byte, error) {

	if len(publicKey) != 32 {
		return nil, nil, errors.New("public key must be 32 bytes")
	}
	if len(blockHash) != 32 {
		return nil, nil, errors.New("block hash must be 32 bytes")
	}

	nearPubKey := NEARPublicKey{
		KeyType: 0, // Ed25519
		Data:    publicKey,
	}

	transferAction := TransferAction{
		Deposit: amount,
	}

	action := Action{
		Type: ActionTypeTransfer,
		Data: transferAction,
	}

	tx := &Transaction{
		SignerID:   signerID,
		PublicKey:  nearPubKey,
		Nonce:      nonce,
		ReceiverID: receiverID,
		BlockHash:  blockHash,
		Actions:    []Action{action},
	}

	// Serialize transaction for signing
	serialized, err := SerializeTransaction(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize transaction: %w", err)
	}

	return tx, serialized, nil
}

// BuildFunctionCallTransaction creates a function call transaction.
func BuildFunctionCallTransaction(signerID, receiverID, methodName string, args []byte,
	gas uint64, deposit *big.Int, nonce uint64, blockHash []byte, publicKey []byte,
	isTestnet bool) (*Transaction, []byte, error) {

	if len(publicKey) != 32 {
		return nil, nil, errors.New("public key must be 32 bytes")
	}

	nearPubKey := NEARPublicKey{
		KeyType: 0, // Ed25519
		Data:    publicKey,
	}

	functionCallAction := FunctionCallAction{
		MethodName: methodName,
		Args:       args,
		Gas:        gas,
		Deposit:    deposit,
	}

	action := Action{
		Type: ActionTypeFunctionCall,
		Data: functionCallAction,
	}

	tx := &Transaction{
		SignerID:   signerID,
		PublicKey:  nearPubKey,
		Nonce:      nonce,
		ReceiverID: receiverID,
		BlockHash:  blockHash,
		Actions:    []Action{action},
	}

	serialized, err := SerializeTransaction(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize transaction: %w", err)
	}

	return tx, serialized, nil
}

// BuildStakeTransaction creates a staking transaction.
func BuildStakeTransaction(signerID, validatorID string, stakeAmount *big.Int,
	nonce uint64, blockHash []byte, publicKey []byte, isTestnet bool) (*Transaction, []byte, error) {

	if len(publicKey) != 32 {
		return nil, nil, errors.New("public key must be 32 bytes")
	}

	nearPubKey := NEARPublicKey{
		KeyType: 0, // Ed25519
		Data:    publicKey,
	}

	stakeAction := StakeAction{
		Stake:     stakeAmount,
		PublicKey: nearPubKey,
	}

	action := Action{
		Type: ActionTypeStake,
		Data: stakeAction,
	}

	tx := &Transaction{
		SignerID:   signerID,
		PublicKey:  nearPubKey,
		Nonce:      nonce,
		ReceiverID: validatorID,
		BlockHash:  blockHash,
		Actions:    []Action{action},
	}

	serialized, err := SerializeTransaction(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("serialize transaction: %w", err)
	}

	return tx, serialized, nil
}

// AttachSignature attaches Ed25519 signature to transaction.
func AttachSignature(tx *Transaction, signature []byte) (*SignedTransaction, error) {
	if len(signature) != 64 {
		return nil, errors.New("Ed25519 signature must be 64 bytes")
	}

	signedTx := &SignedTransaction{
		Transaction: tx,
		Signature: Signature{
			KeyType:   0, // Ed25519
			Signature: signature,
		},
	}

	return signedTx, nil
}

// SignedTransaction represents a signed NEAR transaction
type SignedTransaction struct {
	Transaction *Transaction
	Signature   Signature
}

// Signature represents a NEAR signature
type Signature struct {
	KeyType   uint8
	Signature []byte
}

// SerializeTransaction serializes transaction for signing
func SerializeTransaction(tx *Transaction) ([]byte, error) {
	buf := &bytes.Buffer{}

	if err := writeString(buf, tx.SignerID); err != nil {
		return nil, fmt.Errorf("signer id: %w", err)
	}

	if err := writePublicKey(buf, tx.PublicKey); err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}

	if err := binary.Write(buf, binary.LittleEndian, tx.Nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}

	if err := writeString(buf, tx.ReceiverID); err != nil {
		return nil, fmt.Errorf("receiver id: %w", err)
	}

	if len(tx.BlockHash) != 32 {
		return nil, errors.New("block hash must be 32 bytes")
	}
	if _, err := buf.Write(tx.BlockHash); err != nil {
		return nil, fmt.Errorf("block hash: %w", err)
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(tx.Actions))); err != nil {
		return nil, fmt.Errorf("actions len: %w", err)
	}

	for _, action := range tx.Actions {
		if err := buf.WriteByte(action.Type); err != nil {
			return nil, fmt.Errorf("action type: %w", err)
		}

		switch action.Type {
		case ActionTypeTransfer:
			transfer, ok := action.Data.(TransferAction)
			if !ok {
				return nil, errors.New("invalid transfer action payload")
			}
			if err := writeU128(buf, transfer.Deposit); err != nil {
				return nil, fmt.Errorf("transfer deposit: %w", err)
			}

		case ActionTypeFunctionCall:
			funcCall, ok := action.Data.(FunctionCallAction)
			if !ok {
				return nil, errors.New("invalid function call payload")
			}

			if err := writeString(buf, funcCall.MethodName); err != nil {
				return nil, fmt.Errorf("method name: %w", err)
			}

			if err := binary.Write(buf, binary.LittleEndian, uint32(len(funcCall.Args))); err != nil {
				return nil, fmt.Errorf("args len: %w", err)
			}
			if _, err := buf.Write(funcCall.Args); err != nil {
				return nil, fmt.Errorf("args: %w", err)
			}

			if err := binary.Write(buf, binary.LittleEndian, funcCall.Gas); err != nil {
				return nil, fmt.Errorf("gas: %w", err)
			}

			if err := writeU128(buf, funcCall.Deposit); err != nil {
				return nil, fmt.Errorf("function call deposit: %w", err)
			}

		case ActionTypeStake:
			stake, ok := action.Data.(StakeAction)
			if !ok {
				return nil, errors.New("invalid stake payload")
			}

			if err := writeU128(buf, stake.Stake); err != nil {
				return nil, fmt.Errorf("stake amount: %w", err)
			}
			if err := writePublicKey(buf, stake.PublicKey); err != nil {
				return nil, fmt.Errorf("stake public key: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported action type %d", action.Type)
		}
	}

	return buf.Bytes(), nil
}

// HashTransaction creates hash for signing
func HashTransaction(serialized []byte) [32]byte {
	return sha256.Sum256(serialized)
}

// SerializeSignedTransaction serializes transaction + signature (Borsh) for RPC submission.
func SerializeSignedTransaction(st *SignedTransaction) ([]byte, error) {
	if st == nil || st.Transaction == nil {
		return nil, errors.New("signed transaction is nil")
	}

	if len(st.Signature.Signature) != 64 {
		return nil, errors.New("signature must be 64 bytes")
	}

	serializedTx, err := SerializeTransaction(st.Transaction)
	if err != nil {
		return nil, fmt.Errorf("serialize transaction: %w", err)
	}

	buf := &bytes.Buffer{}
	if _, err := buf.Write(serializedTx); err != nil {
		return nil, fmt.Errorf("write tx: %w", err)
	}
	if err := buf.WriteByte(st.Signature.KeyType); err != nil {
		return nil, fmt.Errorf("write key type: %w", err)
	}
	if _, err := buf.Write(st.Signature.Signature); err != nil {
		return nil, fmt.Errorf("write signature: %w", err)
	}

	return buf.Bytes(), nil
}

// EncodeSignedTransactionBase64 returns base64 ready for NEAR RPC broadcast.
func EncodeSignedTransactionBase64(st *SignedTransaction) (string, error) {
	raw, err := SerializeSignedTransaction(st)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// BuildSignature64 creates a 64-byte Ed25519 signature for NEAR.
func BuildSignature64(hash [32]byte, privateKey []byte) ([]byte, error) {
	if len(privateKey) != 64 {
		return nil, errors.New("Ed25519 private key must be 64 bytes")
	}

	signature := ed25519.Sign(privateKey, hash[:])
	if len(signature) != 64 {
		return nil, errors.New("invalid signature length")
	}

	return signature, nil
}

// VerifySignature verifies Ed25519 signature
func VerifySignature(publicKey, message, signature []byte) bool {
	if len(publicKey) != 32 || len(signature) != 64 {
		return false
	}
	return ed25519.Verify(publicKey, message, signature)
}

// EncodeBase58 encodes bytes to base58
func EncodeBase58(data []byte) string {
	return base58.Encode(data)
}

// DecodeBase58 decodes base58 string to bytes
func DecodeBase58(s string) ([]byte, error) {
	decoded := base58.Decode(s)
	return decoded, nil
}

// GetDefaultGas returns default gas amounts for different operations
func GetDefaultGas(operationType string) uint64 {
	switch operationType {
	case "transfer":
		return 30000000000000 // 30 TGas
	case "function_call":
		return 100000000000000 // 100 TGas
	case "stake":
		return 50000000000000 // 50 TGas
	default:
		return 30000000000000
	}
}

// GetDefaultDeposit returns default deposit amounts
func GetDefaultDeposit(operationType string) *big.Int {
	switch operationType {
	case "transfer":
		return big.NewInt(1) // 1 yoctoNEAR (minimal)
	case "function_call":
		return big.NewInt(0) // No deposit by default
	case "stake":
		return big.NewInt(0) // Stake amount is separate
	default:
		return big.NewInt(1)
	}
}

// ConvertNEARToYocto converts NEAR to yoctoNEAR (1 NEAR = 10^24 yoctoNEAR)
func ConvertNEARToYocto(nearAmount float64) *big.Int {
	yoctoPerNEAR := new(big.Int)
	yoctoPerNEAR.Exp(big.NewInt(10), big.NewInt(24), nil)

	nearBig := big.NewFloat(nearAmount)
	yoctoBig := new(big.Float).Mul(nearBig, new(big.Float).SetInt(yoctoPerNEAR))

	result := new(big.Int)
	yoctoBig.Int(result)
	return result
}

// ConvertYoctoToNEAR converts yoctoNEAR to NEAR
func ConvertYoctoToNEAR(yoctoAmount *big.Int) float64 {
	yoctoPerNEAR := new(big.Int)
	yoctoPerNEAR.Exp(big.NewInt(10), big.NewInt(24), nil)

	yoctoFloat := new(big.Float).SetInt(yoctoAmount)
	nearFloat := new(big.Float).Quo(yoctoFloat, new(big.Float).SetInt(yoctoPerNEAR))

	result, _ := nearFloat.Float64()
	return result
}

func writeString(buf *bytes.Buffer, v string) error {
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(v))); err != nil {
		return err
	}
	_, err := buf.Write([]byte(v))
	return err
}

func writeU128(buf *bytes.Buffer, v *big.Int) error {
	if v == nil || v.Sign() < 0 {
		return errors.New("u128 value must be non-negative")
	}
	bytesLE := make([]byte, 16)
	valBytes := v.Bytes()
	if len(valBytes) > 16 {
		return errors.New("u128 overflow")
	}
	// NEAR expects little-endian u128
	for i := 0; i < len(valBytes); i++ {
		bytesLE[i] = valBytes[len(valBytes)-1-i]
	}
	_, err := buf.Write(bytesLE)
	return err
}

func writePublicKey(buf *bytes.Buffer, pk NEARPublicKey) error {
	if pk.KeyType != 0 {
		return errors.New("unsupported key type (expected Ed25519 = 0)")
	}
	if len(pk.Data) != 32 {
		return errors.New("public key must be 32 bytes")
	}
	if err := buf.WriteByte(pk.KeyType); err != nil {
		return err
	}
	_, err := buf.Write(pk.Data)
	return err
}
