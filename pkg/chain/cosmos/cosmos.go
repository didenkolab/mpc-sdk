package cosmos

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/ethereum/go-ethereum/crypto"
)

// DeriveAddress returns the bech32 account address (hrp such as "cosmos") of
// a compressed secp256k1 public key: RIPEMD160(SHA256(compressedPub)), as
// defined by the Cosmos SDK.
func DeriveAddress(compressedPub []byte, hrp string) (string, error) {
	if len(compressedPub) != 33 {
		return "", errors.New("compressed pubkey must be 33 bytes")
	}
	if _, err := crypto.DecompressPubkey(compressedPub); err != nil {
		return "", err
	}
	conv, err := bech32.ConvertBits(btcutil.Hash160(compressedPub), 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(hrp, conv)
}

// HashSignDoc returns SHA-256(signBytes) for Cosmos sign bytes.
func HashSignDoc(signBytes []byte) [32]byte {
	return sha256.Sum256(signBytes)
}

// HexSignDoc returns hex-encoded sign doc hash (helper).
func HexSignDoc(signBytes []byte) string {
	h := HashSignDoc(signBytes)
	return hex.EncodeToString(h[:])
}

// TransferMsg represents a basic bank transfer message.
type TransferMsg struct {
	FromAddress string `json:"from_address"`
	ToAddress   string `json:"to_address"`
	Amount      []Coin `json:"amount"`
}

// DelegateMsg represents a staking delegation message.
type DelegateMsg struct {
	DelegatorAddress string `json:"delegator_address"`
	ValidatorAddress string `json:"validator_address"`
	Amount           Coin   `json:"amount"`
}

// UndelegateMsg represents a staking undelegation message.
type UndelegateMsg struct {
	DelegatorAddress string `json:"delegator_address"`
	ValidatorAddress string `json:"validator_address"`
	Amount           Coin   `json:"amount"`
}

// VoteMsg represents a governance vote message.
type VoteMsg struct {
	ProposalID string     `json:"proposal_id"`
	Voter      string     `json:"voter"`
	Option     VoteOption `json:"option"`
}

// Coin represents a denomination and amount.
type Coin struct {
	Denom  string `json:"denom"`
	Amount string `json:"amount"`
}

// VoteOption represents governance vote options.
type VoteOption string

const (
	VoteOptionYes        VoteOption = "VOTE_OPTION_YES"
	VoteOptionAbstain    VoteOption = "VOTE_OPTION_ABSTAIN"
	VoteOptionNo         VoteOption = "VOTE_OPTION_NO"
	VoteOptionNoWithVeto VoteOption = "VOTE_OPTION_NO_WITH_VETO"
)

// TxBody represents the transaction body.
type TxBody struct {
	Messages      []json.RawMessage `json:"messages"`
	Memo          string            `json:"memo,omitempty"`
	TimeoutHeight uint64            `json:"timeout_height,omitempty"`
}

// AuthInfo represents authentication information.
type AuthInfo struct {
	SignerInfos []SignerInfo `json:"signer_infos"`
	Fee         Fee          `json:"fee"`
}

// SignerInfo represents signer information.
type SignerInfo struct {
	PublicKey PublicKey `json:"public_key"`
	ModeInfo  ModeInfo  `json:"mode_info"`
	Sequence  uint64    `json:"sequence"`
}

// PublicKey represents a public key.
type PublicKey struct {
	Type string `json:"@type"`
	Key  string `json:"key"` // base64 encoded compressed pubkey
}

// ModeInfo represents the signing mode.
type ModeInfo struct {
	Single SingleMode `json:"single"`
}

// SingleMode represents single signature mode.
type SingleMode struct {
	Mode string `json:"mode"`
}

// Fee represents transaction fees.
type Fee struct {
	Amount   []Coin `json:"amount"`
	GasLimit uint64 `json:"gas_limit"`
	Payer    string `json:"payer,omitempty"`
	Granter  string `json:"granter,omitempty"`
}

// SignDoc represents the document to be signed.
type SignDoc struct {
	BodyBytes     []byte `json:"body_bytes"`
	AuthInfoBytes []byte `json:"auth_info_bytes"`
	ChainID       string `json:"chain_id"`
	AccountNumber uint64 `json:"account_number"`
}

// BuildTransferTx creates a simple transfer transaction.
func BuildTransferTx(fromAddr, toAddr string, amount []Coin, sequence, accountNumber uint64,
	chainID string, fee Fee, memo string, compressedPub []byte) (*SignDoc, error) {

	transferMsg := TransferMsg{
		FromAddress: fromAddr,
		ToAddress:   toAddr,
		Amount:      amount,
	}

	msgWithType := struct {
		Type        string `json:"@type"`
		FromAddress string `json:"from_address"`
		ToAddress   string `json:"to_address"`
		Amount      []Coin `json:"amount"`
	}{
		Type:        "/cosmos.bank.v1beta1.MsgSend",
		FromAddress: transferMsg.FromAddress,
		ToAddress:   transferMsg.ToAddress,
		Amount:      transferMsg.Amount,
	}

	msgBytes, err := json.Marshal(msgWithType)
	if err != nil {
		return nil, err
	}

	txBody := TxBody{
		Messages: []json.RawMessage{msgBytes},
		Memo:     memo,
	}

	return buildSignDoc(txBody, sequence, accountNumber, chainID, fee, compressedPub)
}

// BuildDelegateTx creates a staking delegation transaction.
func BuildDelegateTx(delegatorAddr, validatorAddr string, amount Coin, sequence, accountNumber uint64,
	chainID string, fee Fee, memo string, compressedPub []byte) (*SignDoc, error) {

	delegateMsg := DelegateMsg{
		DelegatorAddress: delegatorAddr,
		ValidatorAddress: validatorAddr,
		Amount:           amount,
	}

	msgWithType := struct {
		Type             string `json:"@type"`
		DelegatorAddress string `json:"delegator_address"`
		ValidatorAddress string `json:"validator_address"`
		Amount           Coin   `json:"amount"`
	}{
		Type:             "/cosmos.staking.v1beta1.MsgDelegate",
		DelegatorAddress: delegateMsg.DelegatorAddress,
		ValidatorAddress: delegateMsg.ValidatorAddress,
		Amount:           delegateMsg.Amount,
	}

	msgBytes, err := json.Marshal(msgWithType)
	if err != nil {
		return nil, err
	}

	txBody := TxBody{
		Messages: []json.RawMessage{msgBytes},
		Memo:     memo,
	}

	return buildSignDoc(txBody, sequence, accountNumber, chainID, fee, compressedPub)
}

// BuildUndelegateTx creates a staking undelegation transaction.
func BuildUndelegateTx(delegatorAddr, validatorAddr string, amount Coin, sequence, accountNumber uint64,
	chainID string, fee Fee, memo string, compressedPub []byte) (*SignDoc, error) {

	undelegateMsg := UndelegateMsg{
		DelegatorAddress: delegatorAddr,
		ValidatorAddress: validatorAddr,
		Amount:           amount,
	}

	msgWithType := struct {
		Type             string `json:"@type"`
		DelegatorAddress string `json:"delegator_address"`
		ValidatorAddress string `json:"validator_address"`
		Amount           Coin   `json:"amount"`
	}{
		Type:             "/cosmos.staking.v1beta1.MsgUndelegate",
		DelegatorAddress: undelegateMsg.DelegatorAddress,
		ValidatorAddress: undelegateMsg.ValidatorAddress,
		Amount:           undelegateMsg.Amount,
	}

	msgBytes, err := json.Marshal(msgWithType)
	if err != nil {
		return nil, err
	}

	txBody := TxBody{
		Messages: []json.RawMessage{msgBytes},
		Memo:     memo,
	}

	return buildSignDoc(txBody, sequence, accountNumber, chainID, fee, compressedPub)
}

// BuildVoteTx creates a governance vote transaction.
func BuildVoteTx(voter, proposalID string, option VoteOption, sequence, accountNumber uint64,
	chainID string, fee Fee, memo string, compressedPub []byte) (*SignDoc, error) {

	voteMsg := VoteMsg{
		ProposalID: proposalID,
		Voter:      voter,
		Option:     option,
	}

	msgWithType := struct {
		Type       string     `json:"@type"`
		ProposalID string     `json:"proposal_id"`
		Voter      string     `json:"voter"`
		Option     VoteOption `json:"option"`
	}{
		Type:       "/cosmos.gov.v1beta1.MsgVote",
		ProposalID: voteMsg.ProposalID,
		Voter:      voteMsg.Voter,
		Option:     voteMsg.Option,
	}

	msgBytes, err := json.Marshal(msgWithType)
	if err != nil {
		return nil, err
	}

	txBody := TxBody{
		Messages: []json.RawMessage{msgBytes},
		Memo:     memo,
	}

	return buildSignDoc(txBody, sequence, accountNumber, chainID, fee, compressedPub)
}

func buildSignDoc(txBody TxBody, sequence, accountNumber uint64, chainID string,
	fee Fee, compressedPub []byte) (*SignDoc, error) {

	// Create auth info
	pubKeyBase64 := base64.StdEncoding.EncodeToString(compressedPub)

	authInfo := AuthInfo{
		SignerInfos: []SignerInfo{{
			PublicKey: PublicKey{
				Type: "/cosmos.crypto.secp256k1.PubKey",
				Key:  pubKeyBase64,
			},
			ModeInfo: ModeInfo{
				Single: SingleMode{
					Mode: "SIGN_MODE_DIRECT",
				},
			},
			Sequence: sequence,
		}},
		Fee: fee,
	}

	bodyBytes, err := json.Marshal(txBody)
	if err != nil {
		return nil, err
	}

	authInfoBytes, err := json.Marshal(authInfo)
	if err != nil {
		return nil, err
	}

	signDoc := &SignDoc{
		BodyBytes:     bodyBytes,
		AuthInfoBytes: authInfoBytes,
		ChainID:       chainID,
		AccountNumber: accountNumber,
	}

	return signDoc, nil
}

// SignBytes returns JSON bytes of SignDoc (deterministic for structs).
func SignBytes(doc *SignDoc) ([]byte, error) {
	return json.Marshal(doc)
}
