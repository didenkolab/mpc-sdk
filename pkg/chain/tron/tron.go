package tron

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/sha3"
)

// DeriveAddress returns a Tron base58-check address from a compressed secp256k1 pubkey.
// Tron address = base58check(0x41 || keccak(pubkey[1:])[12:]).
func DeriveAddress(compressedPub []byte) (string, error) {
	if len(compressedPub) != 33 {
		return "", errors.New("compressed pubkey must be 33 bytes")
	}
	pk, err := crypto.DecompressPubkey(compressedPub)
	if err != nil {
		return "", err
	}
	uncompressed := crypto.FromECDSAPub(pk)[1:] // drop 0x04
	hash := keccak256(uncompressed)
	raw := append([]byte{0x41}, hash[12:]...) // last 20 bytes with 0x41 prefix
	cs := checksum(raw)
	addr := append(raw, cs...)
	return base58.Encode(addr), nil
}

// HashPayload hashes payload for signing using SHA-256 (Tron raw_data hash).
func HashPayload(payload []byte) [32]byte {
	return sha256.Sum256(payload)
}

func keccak256(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func checksum(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:4]
}

// PackAmount converts amount in SUN to big endian bytes (for simple builders).
func PackAmount(v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return buf[:]
}

// contract types in Tron protocol
const (
	ContractTypeTransferID             = 1
	ContractTypeTriggerSmartContractID = 31
)

// TRXTransferContract represents a TRX transfer contract.
type TRXTransferContract struct {
	OwnerAddress string `json:"owner_address"`
	ToAddress    string `json:"to_address"`
	Amount       uint64 `json:"amount"`
}

// TRC20TransferContract represents a TRC20 token transfer.
type TRC20TransferContract struct {
	OwnerAddress     string `json:"owner_address"`
	ContractAddress  string `json:"contract_address"`
	FunctionSelector string `json:"function_selector"`
	Parameter        string `json:"parameter"`
	CallValue        uint64 `json:"call_value,omitempty"`
}

// Transaction represents a Tron transaction.
type Transaction struct {
	RawData   RawData     `json:"raw_data"`
	Signature []string    `json:"signature,omitempty"`
	Ret       []RetResult `json:"ret,omitempty"`
}

// RawData represents the raw data of a transaction.
type RawData struct {
	Contract      []Contract `json:"contract"`
	RefBlockBytes []byte     `json:"ref_block_bytes"`
	RefBlockHash  []byte     `json:"ref_block_hash"`
	Expiration    int64      `json:"expiration"`
	Timestamp     int64      `json:"timestamp"`
	FeeLimit      uint64     `json:"fee_limit,omitempty"`
}

// Contract represents a transaction contract.
type Contract struct {
	Type      ContractType `json:"type"`
	Parameter Parameter    `json:"parameter"`
}

// Parameter represents contract parameters.
type Parameter struct {
	Value   any    `json:"value"`
	TypeURL string `json:"type_url"`
}

// ContractType represents the type of contract.
type ContractType string

const (
	ContractTypeTransfer             ContractType = "TransferContract"
	ContractTypeTriggerSmartContract ContractType = "TriggerSmartContract"
)

// RetResult represents transaction result.
type RetResult struct {
	ContractRet string `json:"contractRet,omitempty"`
}

// BuildTRXTransfer creates a TRX transfer transaction.
func BuildTRXTransfer(fromAddr, toAddr string, amount uint64, refBlockBytes, refBlockHash string,
	expiration, timestamp int64) (*Transaction, []byte, error) {
	if !isValidTronAddress(fromAddr) || !isValidTronAddress(toAddr) {
		return nil, nil, errors.New("invalid Tron address format")
	}

	refBytes, err := hex.DecodeString(refBlockBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ref_block_bytes hex: %w", err)
	}
	refHash, err := hex.DecodeString(refBlockHash)
	if err != nil {
		return nil, nil, fmt.Errorf("ref_block_hash hex: %w", err)
	}

	contract := TRXTransferContract{
		OwnerAddress: fromAddr,
		ToAddress:    toAddr,
		Amount:       amount,
	}

	rawData := RawData{
		Contract: []Contract{{
			Type: ContractTypeTransfer,
			Parameter: Parameter{
				Value:   contract,
				TypeURL: "type.googleapis.com/protocol.TransferContract",
			},
		}},
		RefBlockBytes: refBytes,
		RefBlockHash:  refHash,
		Expiration:    expiration,
		Timestamp:     timestamp,
	}

	tx := &Transaction{
		RawData: rawData,
	}

	rawBytes, err := serializeRawData(rawData)
	if err != nil {
		return nil, nil, err
	}

	return tx, rawBytes, nil
}

// BuildTRC20Transfer creates a TRC20 token transfer transaction.
func BuildTRC20Transfer(fromAddr, contractAddr, toAddr string, amount uint64,
	refBlockBytes, refBlockHash string, expiration, timestamp int64, feeLimit uint64) (*Transaction, []byte, error) {

	// Validate addresses
	if !isValidTronAddress(fromAddr) || !isValidTronAddress(toAddr) || !isValidTronAddress(contractAddr) {
		return nil, nil, errors.New("invalid Tron address format")
	}

	refBytes, err := hex.DecodeString(refBlockBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ref_block_bytes hex: %w", err)
	}
	refHash, err := hex.DecodeString(refBlockHash)
	if err != nil {
		return nil, nil, fmt.Errorf("ref_block_hash hex: %w", err)
	}

	// Build TRC20 transfer function call: transfer(address,uint256)
	// Function selector: a9059cbb (first 4 bytes of keccak256("transfer(address,uint256)"))
	functionSelector := "a9059cbb"

	// Encode parameters: to_address (32 bytes) + amount (32 bytes)
	toAddrHex, err := base58AddressToHex(toAddr)
	if err != nil {
		return nil, nil, err
	}

	// Pad address to 32 bytes (remove 0x41 prefix, pad left with zeros)
	paddedAddr := fmt.Sprintf("%064s", toAddrHex[2:])

	// Pad amount to 32 bytes
	paddedAmount := fmt.Sprintf("%064x", amount)

	parameter := functionSelector + paddedAddr + paddedAmount

	contract := TRC20TransferContract{
		OwnerAddress:     fromAddr,
		ContractAddress:  contractAddr,
		FunctionSelector: functionSelector,
		Parameter:        parameter,
		CallValue:        0, // TRC20 transfers don't send TRX
	}

	rawData := RawData{
		Contract: []Contract{{
			Type: ContractTypeTriggerSmartContract,
			Parameter: Parameter{
				Value:   contract,
				TypeURL: "type.googleapis.com/protocol.TriggerSmartContract",
			},
		}},
		RefBlockBytes: refBytes,
		RefBlockHash:  refHash,
		Expiration:    expiration,
		Timestamp:     timestamp,
		FeeLimit:      feeLimit,
	}

	tx := &Transaction{
		RawData: rawData,
	}

	// Serialize for signing
	payload, err := serializeRawData(rawData)
	if err != nil {
		return nil, nil, err
	}

	return tx, payload, nil
}

// AttachSignature attaches a signature to the transaction.
func AttachSignature(tx *Transaction, signature []byte) {
	sig := hex.EncodeToString(signature)
	tx.Signature = append(tx.Signature, sig)
}

// serializeRawData serializes raw data using Tron protobuf field numbers (minimal subset).
// Field numbers:
// 1: ref_block_bytes (bytes)
// 4: ref_block_hash (bytes)
// 8: expiration (int64)
// 11: contract (repeated)
// 14: timestamp (int64)
// 18: fee_limit (int64)
func serializeRawData(rawData RawData) ([]byte, error) {
	buf := &bytes.Buffer{}

	// ref_block_bytes (field 1)
	if len(rawData.RefBlockBytes) > 0 {
		if err := writeBytesField(buf, 1, rawData.RefBlockBytes); err != nil {
			return nil, err
		}
	}

	// ref_block_hash (field 4)
	if len(rawData.RefBlockHash) > 0 {
		if err := writeBytesField(buf, 4, rawData.RefBlockHash); err != nil {
			return nil, err
		}
	}

	// expiration (field 8)
	if err := writeInt64Field(buf, 8, rawData.Expiration); err != nil {
		return nil, err
	}

	// contract (field 11)
	for _, c := range rawData.Contract {
		contractBytes, err := serializeContract(c)
		if err != nil {
			return nil, err
		}
		if err := writeBytesField(buf, 11, contractBytes); err != nil {
			return nil, err
		}
	}

	// timestamp (field 14)
	if err := writeInt64Field(buf, 14, rawData.Timestamp); err != nil {
		return nil, err
	}

	// fee_limit (field 18) optional
	if rawData.FeeLimit > 0 {
		if err := writeUint64Field(buf, 18, rawData.FeeLimit); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func serializeContract(c Contract) ([]byte, error) {
	buf := &bytes.Buffer{}

	// type (field 1, varint)
	if err := writeUint64Field(buf, 1, contractTypeToID(c.Type)); err != nil {
		return nil, err
	}

	// parameter (field 2, Any message)
	anyBytes, err := serializeAny(c.Parameter)
	if err != nil {
		return nil, err
	}
	if err := writeBytesField(buf, 2, anyBytes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func serializeAny(p Parameter) ([]byte, error) {
	buf := &bytes.Buffer{}
	if p.TypeURL == "" {
		return nil, errors.New("type_url is required")
	}

	if err := writeStringField(buf, 1, p.TypeURL); err != nil {
		return nil, err
	}

	valueBytes, err := serializeContractPayload(p)
	if err != nil {
		return nil, err
	}
	if err := writeBytesField(buf, 2, valueBytes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func serializeContractPayload(p Parameter) ([]byte, error) {
	switch v := p.Value.(type) {
	case TRXTransferContract:
		return serializeTRXTransferContract(v)
	case TRC20TransferContract:
		return serializeTRC20TransferContract(v)
	default:
		return nil, fmt.Errorf("unsupported contract payload %T", v)
	}
}

func serializeTRXTransferContract(c TRXTransferContract) ([]byte, error) {
	from, err := base58AddressBytes(c.OwnerAddress)
	if err != nil {
		return nil, err
	}
	to, err := base58AddressBytes(c.ToAddress)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	if err := writeBytesField(buf, 1, from); err != nil {
		return nil, err
	}
	if err := writeBytesField(buf, 2, to); err != nil {
		return nil, err
	}
	if err := writeUint64Field(buf, 3, c.Amount); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func serializeTRC20TransferContract(c TRC20TransferContract) ([]byte, error) {
	from, err := base58AddressBytes(c.OwnerAddress)
	if err != nil {
		return nil, err
	}
	contractAddr, err := base58AddressBytes(c.ContractAddress)
	if err != nil {
		return nil, err
	}

	// parameter field in TriggerSmartContract is "data" (field 4) with hex string payload
	paramBytes, err := hex.DecodeString(c.Parameter)
	if err != nil {
		return nil, fmt.Errorf("parameter hex: %w", err)
	}

	buf := &bytes.Buffer{}
	if err := writeBytesField(buf, 1, from); err != nil {
		return nil, err
	}
	if err := writeBytesField(buf, 2, contractAddr); err != nil {
		return nil, err
	}
	if err := writeUint64Field(buf, 3, c.CallValue); err != nil {
		return nil, err
	}
	if err := writeBytesField(buf, 4, paramBytes); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func base58AddressBytes(addr string) ([]byte, error) {
	decoded, err := base58.Decode(addr)
	if err != nil {
		return nil, fmt.Errorf("base58 decode: %w", err)
	}
	if len(decoded) != 25 {
		return nil, errors.New("invalid address length")
	}
	payload := decoded[:21]
	if !bytesEqual(decoded[21:], checksum(payload)) {
		return nil, errors.New("invalid checksum")
	}
	return payload, nil
}

// isValidTronAddress checks if an address is a valid Tron address.
func isValidTronAddress(addr string) bool {
	if len(addr) != 34 {
		return false
	}

	// Decode base58
	decoded, err := base58.Decode(addr)
	if err != nil {
		return false
	}

	// Check length (21 bytes address + 4 bytes checksum)
	if len(decoded) != 25 {
		return false
	}

	// Check prefix (should be 0x41 for mainnet)
	if decoded[0] != 0x41 {
		return false
	}

	// Verify checksum
	payload := decoded[:21]
	providedChecksum := decoded[21:]
	calculatedChecksum := checksum(payload)

	return bytesEqual(providedChecksum, calculatedChecksum)
}

// base58AddressToHex converts base58 Tron address to hex representation.
func base58AddressToHex(addr string) (string, error) {
	payload, err := base58AddressBytes(addr)
	if err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(payload), nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func encodeVarint(v uint64) []byte {
	var buf []byte
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}

func writeBytesField(buf *bytes.Buffer, fieldNumber int, value []byte) error {
	if len(value) == 0 {
		return nil
	}
	tag := byte((fieldNumber << 3) | 2)
	if err := buf.WriteByte(tag); err != nil {
		return err
	}
	if _, err := buf.Write(encodeVarint(uint64(len(value)))); err != nil {
		return err
	}
	_, err := buf.Write(value)
	return err
}

func writeStringField(buf *bytes.Buffer, fieldNumber int, value string) error {
	return writeBytesField(buf, fieldNumber, []byte(value))
}

func writeUint64Field(buf *bytes.Buffer, fieldNumber int, value uint64) error {
	tag := byte(fieldNumber << 3) // wire type 0 (varint)
	if err := buf.WriteByte(tag); err != nil {
		return err
	}
	_, err := buf.Write(encodeVarint(value))
	return err
}

func writeInt64Field(buf *bytes.Buffer, fieldNumber int, value int64) error {
	return writeUint64Field(buf, fieldNumber, uint64(value))
}

func contractTypeToID(t ContractType) uint64 {
	switch t {
	case ContractTypeTransfer:
		return ContractTypeTransferID
	case ContractTypeTriggerSmartContract:
		return ContractTypeTriggerSmartContractID
	default:
		return 0
	}
}
