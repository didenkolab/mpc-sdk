// Package frost provides Go bindings for threshold Ed25519 signatures based on
// FROST (Flexible Round-Optimized Schnorr Threshold signatures).
//
// The cryptography is implemented by the Zcash Foundation frost-ed25519 crate
// and exposed through the mpc_frost_ffi C ABI. This package is a thin, typed
// wrapper: it owns the lifetime of the native state objects and converts
// between Go values and the JSON wire format used by the FFI.
//
// Party identifiers are one-based (1..n). Round 2 DKG output is a JSON array
// of point-to-point packets, each addressed to a single recipient through a
// zero-based "to_id" field; use Round2MessagesFor to select the packets that
// belong to a given party before calling DKGState.HandleMsg2.
//
// All state objects must be released with Free once they are no longer
// needed. They are not safe for concurrent use.
package frost

/*
#cgo windows LDFLAGS: -L${SRCDIR}/../../internal/rust/target/x86_64-pc-windows-gnu/release -static -Wl,--allow-multiple-definition -lmpc_frost_ffi -lws2_32 -luserenv -lbcrypt -lntdll
#cgo linux LDFLAGS: -L${SRCDIR}/../../internal/rust/target/release -lmpc_frost_ffi -lpthread -ldl -lm
#cgo darwin,!ios LDFLAGS: -L${SRCDIR}/../../internal/rust/target/release -lmpc_frost_ffi -framework Security
#cgo darwin,ios LDFLAGS: -L${SRCDIR}/../../internal/rust/target/ios-universal -lmpc_frost_ffi -framework Security
#cgo android,arm64 LDFLAGS: -L${SRCDIR}/../../internal/rust/target/aarch64-linux-android/release -lmpc_frost_ffi -llog -ldl -lm
#cgo android,amd64 LDFLAGS: -L${SRCDIR}/../../internal/rust/target/x86_64-linux-android/release -lmpc_frost_ffi -llog -ldl -lm
#cgo android,arm LDFLAGS: -L${SRCDIR}/../../internal/rust/target/armv7-linux-androideabi/release -lmpc_frost_ffi -llog -ldl -lm
#include <stdlib.h>

typedef void* DkgState;
typedef void* SigningState;

// Error handling
char* frost_get_last_error();
void frost_free_string(char* s);

// DKG functions
DkgState frost_dkg_init(unsigned short party_id, unsigned short participants, unsigned short threshold);
char* frost_dkg_generate_msg1(DkgState state);
char* frost_dkg_handle_msg1(DkgState state, const char* msgs_json);
char* frost_dkg_handle_msg2(DkgState state, const char* msgs_json);
char* frost_dkg_finalize(DkgState state);
void frost_dkg_free_state(DkgState state);

// Signing functions
SigningState frost_signing_init(const char* keyshare_json, const unsigned char* message_hash, size_t message_len);
char* frost_signing_generate_msg1(SigningState state);
char* frost_signing_handle_msg1(SigningState state, const char* msgs_json);
char* frost_signing_generate_msg2(SigningState state);
char* frost_signing_handle_msg2(SigningState state, const char* msgs_json);
void frost_signing_free_state(SigningState state);

// Signature functions
char* frost_create_partial_signature(const char* presig_json, const unsigned char* message_hash);
char* frost_combine_signatures(const char* partial_sig_json, const char* msg_list_json);

// Utility functions
char* frost_derive_public_key(const char* keyshare_json, const char* derivation_path);
char* frost_derive_keyshare(const char* keyshare_json, const char* derivation_path);
char* frost_verify_signature(const char* public_key, const unsigned char* message, size_t message_len, const char* signature);
*/
import "C"

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"runtime"
	"unsafe"
)

// ============ FFI helpers ============

// lastError reads the thread-local error recorded by the FFI. It must be
// called on the same OS thread as the failing call.
func lastError() error {
	cErr := C.frost_get_last_error()
	if cErr == nil {
		return ErrFFICall
	}
	defer C.frost_free_string(cErr)
	msg := C.GoString(cErr)
	if msg == "" {
		return ErrFFICall
	}
	return fmt.Errorf("%w: %s", ErrFFICall, msg)
}

// callString invokes an FFI function returning an owned C string, converts
// the result to Go and frees it. The goroutine is pinned to its OS thread for
// the duration of the call because the FFI reports errors through
// thread-local storage.
func callString(fn func() *C.char) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cResult := fn()
	if cResult == nil {
		return "", lastError()
	}
	defer C.frost_free_string(cResult)
	return C.GoString(cResult), nil
}

// callWithJSON marshals v to JSON, passes it to fn as a C string and returns
// the FFI result.
func callWithJSON(v interface{}, fn func(*C.char) *C.char) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("frost: marshal messages: %w", err)
	}
	cPayload := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cPayload))
	return callString(func() *C.char { return fn(cPayload) })
}

// ============ DKG ============

// DKGState holds one party's state for a FROST distributed key generation.
type DKGState struct {
	ptr C.DkgState
}

// NewDKGState creates the DKG state for party partyID (1..nParties) in a
// threshold-of-nParties scheme. threshold is the minimum number of parties
// required to sign and must be at least 2.
func NewDKGState(partyID uint8, nParties, threshold int) (*DKGState, error) {
	if partyID == 0 || int(partyID) > nParties {
		return nil, ErrInvalidPartyID
	}
	if threshold < 2 || threshold > nParties || nParties > math.MaxUint16 {
		return nil, ErrInvalidThreshold
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	state := C.frost_dkg_init(C.ushort(partyID), C.ushort(nParties), C.ushort(threshold))
	if state == nil {
		return nil, lastError()
	}
	return &DKGState{ptr: state}, nil
}

// NewDKGStateWithRanks mirrors the DKLs23 constructor so callers can switch
// protocols without changing call sites. FROST has no ranked mode, so every
// rank must be zero; the number of parties is len(ranks).
func NewDKGStateWithRanks(partyID uint8, ranks []uint8, threshold int) (*DKGState, error) {
	if len(ranks) == 0 {
		return nil, errors.New("frost: ranks must not be empty")
	}
	for _, r := range ranks {
		if r != 0 {
			return nil, errors.New("frost: ranked mode is not supported; all ranks must be 0")
		}
	}
	return NewDKGState(partyID, len(ranks), threshold)
}

// GenerateMsg1 returns this party's round 1 broadcast message (commitments).
func (s *DKGState) GenerateMsg1() (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callString(func() *C.char { return C.frost_dkg_generate_msg1(s.ptr) })
}

// HandleMsg1 consumes the round 1 messages of every other party (exactly
// n-1 of them) and returns the round 2 output: a JSON array of packets, one
// per recipient. Each packet contains a secret share and must be delivered
// only to its recipient (see Round2MessagesFor).
func (s *DKGState) HandleMsg1(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callWithJSON(msgs, func(p *C.char) *C.char { return C.frost_dkg_handle_msg1(s.ptr, p) })
}

// HandleMsg2 consumes the round 2 packets addressed to this party (exactly
// n-1 of them, one from every other party) and returns the keyshare JSON.
func (s *DKGState) HandleMsg2(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callWithJSON(msgs, func(p *C.char) *C.char { return C.frost_dkg_handle_msg2(s.ptr, p) })
}

// Finalize returns the keyshare produced by HandleMsg2.
func (s *DKGState) Finalize() (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callString(func() *C.char { return C.frost_dkg_finalize(s.ptr) })
}

// Free releases the native state. It is safe to call more than once.
func (s *DKGState) Free() {
	if s != nil && s.ptr != nil {
		C.frost_dkg_free_state(s.ptr)
		s.ptr = nil
	}
}

// round2Header is the routing part of a DKG round 2 packet.
type round2Header struct {
	ToID *uint16 `json:"to_id"`
}

// Round2MessagesFor selects, from the round 2 outputs of the other parties
// (the strings returned by HandleMsg1), the packets addressed to
// partyID. The result can be passed directly to DKGState.HandleMsg2.
//
// Packets addressed to other parties are skipped, so the outputs of all
// parties, including partyID's own, may be passed in.
func Round2MessagesFor(partyID uint8, round2Outputs ...string) ([]interface{}, error) {
	if partyID == 0 {
		return nil, ErrInvalidPartyID
	}
	want := uint16(partyID) - 1 // to_id is zero-based

	var selected []interface{}
	for i, out := range round2Outputs {
		var packets []json.RawMessage
		if err := json.Unmarshal([]byte(out), &packets); err != nil {
			return nil, fmt.Errorf("frost: round 2 output %d: %w", i, err)
		}
		for _, raw := range packets {
			var h round2Header
			if err := json.Unmarshal(raw, &h); err != nil {
				return nil, fmt.Errorf("frost: round 2 output %d: %w", i, err)
			}
			if h.ToID == nil {
				return nil, fmt.Errorf("frost: round 2 output %d: packet without to_id", i)
			}
			if *h.ToID == want {
				selected = append(selected, raw)
			}
		}
	}
	return selected, nil
}

// ============ Signing ============

// SigningState holds one party's state for a FROST signing session.
type SigningState struct {
	ptr C.SigningState
}

// NewSigningState creates a signing state that signs the 32-byte value
// messageHash. Use NewSigningStateForMessage when the protocol requires the
// raw message to be signed (Ed25519 hashes the message internally).
func NewSigningState(keyshareJSON string, messageHash [32]byte) (*SigningState, error) {
	return NewSigningStateForMessage(keyshareJSON, messageHash[:])
}

// NewSigningStateForMessage creates a signing state that signs message as-is.
// All signers must use the same message.
func NewSigningStateForMessage(keyshareJSON string, message []byte) (*SigningState, error) {
	if len(message) == 0 {
		return nil, ErrEmptyMessage
	}
	cKeyshare := C.CString(keyshareJSON)
	defer C.free(unsafe.Pointer(cKeyshare))
	cMsg := C.CBytes(message)
	defer C.free(cMsg)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	state := C.frost_signing_init(cKeyshare, (*C.uchar)(cMsg), C.size_t(len(message)))
	if state == nil {
		return nil, lastError()
	}
	return &SigningState{ptr: state}, nil
}

// GenerateMsg1 returns this signer's round 1 broadcast message (nonce
// commitments). It can be called only once per signing state.
func (s *SigningState) GenerateMsg1() (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callString(func() *C.char { return C.frost_signing_generate_msg1(s.ptr) })
}

// HandleMsg1 consumes the round 1 commitments of the other signers and
// returns this signer's signature share bundle. The nonces are consumed even
// if the call fails, so a signing state cannot be reused.
func (s *SigningState) HandleMsg1(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callWithJSON(msgs, func(p *C.char) *C.char { return C.frost_signing_handle_msg1(s.ptr, p) })
}

// GenerateMsg2 exists for API parity with DKLs23. FROST signing has two
// rounds, so it always returns an empty JSON object.
func (s *SigningState) GenerateMsg2() (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callString(func() *C.char { return C.frost_signing_generate_msg2(s.ptr) })
}

// HandleMsg2 exists for API parity with DKLs23 and always returns an empty
// JSON object.
func (s *SigningState) HandleMsg2(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callWithJSON(msgs, func(p *C.char) *C.char { return C.frost_signing_handle_msg2(s.ptr, p) })
}

// Free releases the native state. It is safe to call more than once.
func (s *SigningState) Free() {
	if s != nil && s.ptr != nil {
		C.frost_signing_free_state(s.ptr)
		s.ptr = nil
	}
}

// ============ Signatures ============

// CreatePartialSignature returns the partial signature for a signer. In FROST
// the signature share is already produced by SigningState.HandleMsg1, so this
// returns presigJSON unchanged; it exists for API parity with DKLs23.
func CreatePartialSignature(presigJSON string, messageHash [32]byte) (string, error) {
	cPresig := C.CString(presigJSON)
	defer C.free(unsafe.Pointer(cPresig))
	return callString(func() *C.char {
		return C.frost_create_partial_signature(cPresig, (*C.uchar)(unsafe.Pointer(&messageHash[0])))
	})
}

// CombineSignatures aggregates the partial signature of one signer with the
// partial signatures of the others (msgList) and returns the 64-byte Ed25519
// signature as hex.
func CombineSignatures(partialSigJSON string, msgList []interface{}) (string, error) {
	cPartial := C.CString(partialSigJSON)
	defer C.free(unsafe.Pointer(cPartial))
	return callWithJSON(msgList, func(p *C.char) *C.char { return C.frost_combine_signatures(cPartial, p) })
}

// ============ Keys ============

// DerivePublicKey returns the group public key as JSON of the form
// {"derived_public_key": "<hex>"}. Ed25519 child key derivation (SLIP-10) is
// not implemented yet: derivationPath must be "m", any other path is an error.
func DerivePublicKey(keyshareJSON, derivationPath string) (string, error) {
	cKeyshare := C.CString(keyshareJSON)
	defer C.free(unsafe.Pointer(cKeyshare))
	cPath := C.CString(derivationPath)
	defer C.free(unsafe.Pointer(cPath))
	return callString(func() *C.char { return C.frost_derive_public_key(cKeyshare, cPath) })
}

// DeriveKeyshare returns the keyshare for derivationPath. Ed25519 child key
// derivation (SLIP-10) is not implemented yet: only the root path "m" is
// accepted, and any other path returns an error.
func DeriveKeyshare(keyshareJSON, derivationPath string) (string, error) {
	cKeyshare := C.CString(keyshareJSON)
	defer C.free(unsafe.Pointer(cKeyshare))
	cPath := C.CString(derivationPath)
	defer C.free(unsafe.Pointer(cPath))
	return callString(func() *C.char { return C.frost_derive_keyshare(cKeyshare, cPath) })
}

// VerifySignature verifies a hex-encoded Ed25519 signature over message.
// publicKey is either the hex public key or the JSON returned by
// DerivePublicKey. A well-formed but invalid signature yields (false, nil).
func VerifySignature(publicKey string, message []byte, signature string) (bool, error) {
	if len(message) == 0 {
		return false, ErrEmptyMessage
	}
	cPubKey := C.CString(publicKey)
	defer C.free(unsafe.Pointer(cPubKey))
	cSig := C.CString(signature)
	defer C.free(unsafe.Pointer(cSig))
	cMsg := C.CBytes(message)
	defer C.free(cMsg)

	res, err := callString(func() *C.char {
		return C.frost_verify_signature(cPubKey, (*C.uchar)(cMsg), C.size_t(len(message)), cSig)
	})
	if err != nil {
		return false, err
	}
	return res == "true", nil
}

// HashMessage returns the SHA-256 digest of message.
func HashMessage(message string) [32]byte {
	return sha256.Sum256([]byte(message))
}
