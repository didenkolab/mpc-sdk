package dkls23

// #cgo windows LDFLAGS: -L${SRCDIR}/../../internal/rust/target/x86_64-pc-windows-gnu/release -static -Wl,--allow-multiple-definition -lmpc_dkls23_ffi -lws2_32 -luserenv -lbcrypt -lntdll
// #cgo linux LDFLAGS: -L${SRCDIR}/../../internal/rust/target/release -Wl,--start-group -lmpc_dkls23_ffi -Wl,--end-group -lpthread -ldl -lm
// #cgo darwin,!ios LDFLAGS: -L${SRCDIR}/../../internal/rust/target/release -lmpc_dkls23_ffi -framework Security
// #cgo darwin,ios LDFLAGS: -L${SRCDIR}/../../internal/rust/target/ios-universal -lmpc_dkls23_ffi -framework Security
// #cgo android,arm64 LDFLAGS: -L${SRCDIR}/../../internal/rust/target/aarch64-linux-android/release -lmpc_dkls23_ffi -llog -ldl -lm
// #cgo android,amd64 LDFLAGS: -L${SRCDIR}/../../internal/rust/target/x86_64-linux-android/release -lmpc_dkls23_ffi -llog -ldl -lm
// #cgo android,arm LDFLAGS: -L${SRCDIR}/../../internal/rust/target/armv7-linux-androideabi/release -lmpc_dkls23_ffi -llog -ldl -lm
// #include <stdlib.h>
//
// typedef void* DkgState;
// typedef void* DsgState;
//
// // Error handling
// char* dkls23_get_last_error();
// void dkls23_free_string(char* s);
//
// // DKG functions
// DkgState dkls23_dkg_init(unsigned char party_id, size_t n_parties, size_t threshold);
// DkgState dkls23_dkg_init_with_ranks(unsigned char party_id, const unsigned char* ranks_ptr, size_t ranks_len, size_t threshold);
// char* dkls23_dkg_generate_msg1(DkgState state);
// char* dkls23_dkg_handle_msg1(DkgState state, const char* msgs_json);
// char* dkls23_dkg_handle_msg2(DkgState state, const char* msgs_json);
// char* dkls23_dkg_calculate_commitment_2(DkgState state);
// char* dkls23_dkg_handle_msg3(DkgState state, const char* msgs_json, const char* commitments_json);
// char* dkls23_dkg_handle_msg4(DkgState state, const char* msgs_json);
// void dkls23_dkg_free_state(DkgState state);
//
// // DSG functions
// DsgState dkls23_dsg_init(const char* keyshare_json, const char* derivation_path);
// char* dkls23_dsg_generate_msg1(DsgState state);
// char* dkls23_dsg_handle_msg1(DsgState state, const char* msgs_json);
// char* dkls23_dsg_handle_msg2(DsgState state, const char* msgs_json);
// char* dkls23_dsg_handle_msg3(DsgState state, const char* msgs_json);
// char* dkls23_create_partial_signature(const char* presig_json, const unsigned char* message_hash);
// char* dkls23_combine_signatures(const char* partial_sig_json, const char* sign_msg4_json);
// void dkls23_dsg_free_state(DsgState state);
//
// // Key derivation
// char* dkls23_derive_public_key(const char* keyshare_json, const char* derivation_path);
// char* dkls23_derive_keyshare(const char* keyshare_json, const char* derivation_path);
import "C"

import (
	"encoding/json"
	"errors"
	"runtime"
	"unsafe"
)

// maxParties is the largest party count addressable with 8-bit party IDs.
const maxParties = 256

// getLastError returns the most recent error recorded by the Rust library on
// the calling OS thread. Callers must hold runtime.LockOSThread across the
// failing FFI call and this call, because the error is stored thread-locally.
func getLastError() error {
	cErr := C.dkls23_get_last_error()
	if cErr == nil {
		return ErrFFICall
	}
	defer C.dkls23_free_string(cErr)
	errMsg := C.GoString(cErr)
	if errMsg == "" {
		return ErrFFICall
	}
	return errors.New("dkls23: " + errMsg)
}

// callString invokes an FFI function returning a Rust-allocated C string,
// converts the result to Go and frees it. A nil result is translated into the
// library's last error. The goroutine is pinned to its OS thread for the
// duration of the call so the thread-local error can be read reliably.
func callString(fn func() *C.char) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	c := fn()
	if c == nil {
		return "", getLastError()
	}
	defer C.dkls23_free_string(c)
	return C.GoString(c), nil
}

// cJSON marshals v and returns it as a C string that the caller must free.
func cJSON(v any) (*C.char, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return C.CString(string(data)), nil
}

// callJSON marshals msgs to a C string, passes it to fn and returns fn's
// result as with callString.
func callJSON(msgs any, fn func(cMsgs *C.char) *C.char) (string, error) {
	cMsgs, err := cJSON(msgs)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cMsgs))
	return callString(func() *C.char { return fn(cMsgs) })
}

// ============ DKG ============

// DKGState holds one party's state for a DKLs23 distributed key generation.
//
// A DKGState is not safe for concurrent use and must be released with Free.
type DKGState struct {
	ptr C.DkgState
}

// NewDKGState creates a DKG state for a standard t-of-n key.
//
// partyID is 0-based and must be less than nParties. threshold is the number
// of parties required to sign and must satisfy 2 <= threshold <= nParties.
func NewDKGState(partyID uint8, nParties, threshold int) (*DKGState, error) {
	if nParties < 2 || nParties > maxParties || int(partyID) >= nParties {
		return nil, ErrInvalidPartyID
	}
	if threshold < 2 || threshold > nParties {
		return nil, ErrInvalidThreshold
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	state := C.dkls23_dkg_init(
		C.uchar(partyID),
		C.size_t(nParties),
		C.size_t(threshold),
	)
	if state == nil {
		return nil, getLastError()
	}
	return &DKGState{ptr: state}, nil
}

// NewDKGStateWithRanks creates a DKG state for a hierarchical (ranked) key.
//
// ranks holds one rank per party, indexed by party ID; rank 0 is the most
// privileged. threshold must satisfy max(ranks) < threshold <= len(ranks).
func NewDKGStateWithRanks(partyID uint8, ranks []uint8, threshold int) (*DKGState, error) {
	if len(ranks) < 2 || len(ranks) > maxParties {
		return nil, ErrInvalidRanks
	}
	if int(partyID) >= len(ranks) {
		return nil, ErrInvalidPartyID
	}
	if threshold < 2 || threshold > len(ranks) {
		return nil, ErrInvalidThreshold
	}
	for _, r := range ranks {
		if int(r) >= threshold {
			return nil, ErrInvalidRanks
		}
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	state := C.dkls23_dkg_init_with_ranks(
		C.uchar(partyID),
		(*C.uchar)(unsafe.Pointer(&ranks[0])),
		C.size_t(len(ranks)),
		C.size_t(threshold),
	)
	if state == nil {
		return nil, getLastError()
	}
	return &DKGState{ptr: state}, nil
}

// GenerateMsg1 returns this party's round-1 message, to be broadcast to all
// other parties.
func (s *DKGState) GenerateMsg1() (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callString(func() *C.char { return C.dkls23_dkg_generate_msg1(s.ptr) })
}

// HandleMsg1 consumes the round-1 messages of all other parties and returns a
// JSON array of point-to-point round-2 messages (route each by its "to_id").
func (s *DKGState) HandleMsg1(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callJSON(msgs, func(cMsgs *C.char) *C.char { return C.dkls23_dkg_handle_msg1(s.ptr, cMsgs) })
}

// HandleMsg2 consumes the round-2 messages addressed to this party and returns
// a JSON array of point-to-point round-3 messages.
func (s *DKGState) HandleMsg2(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callJSON(msgs, func(cMsgs *C.char) *C.char { return C.dkls23_dkg_handle_msg2(s.ptr, cMsgs) })
}

// CalculateCommitment2 returns this party's hex-encoded commitment, which must
// be shared with all parties before HandleMsg3.
func (s *DKGState) CalculateCommitment2() (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callString(func() *C.char { return C.dkls23_dkg_calculate_commitment_2(s.ptr) })
}

// HandleMsg3 consumes the round-3 messages addressed to this party together
// with the commitments of all parties (including its own, ordered by party
// ID) and returns the round-4 message to broadcast.
func (s *DKGState) HandleMsg3(msgs []interface{}, commitments []string) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	cMsgs, err := cJSON(msgs)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cMsgs))

	cCommits, err := cJSON(commitments)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cCommits))

	return callString(func() *C.char { return C.dkls23_dkg_handle_msg3(s.ptr, cMsgs, cCommits) })
}

// HandleMsg4 consumes the round-4 messages of all other parties and returns
// this party's keyshare as JSON.
func (s *DKGState) HandleMsg4(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callJSON(msgs, func(cMsgs *C.char) *C.char { return C.dkls23_dkg_handle_msg4(s.ptr, cMsgs) })
}

// Free releases the native state. It is safe to call more than once.
func (s *DKGState) Free() {
	if s != nil && s.ptr != nil {
		C.dkls23_dkg_free_state(s.ptr)
		s.ptr = nil
	}
}

// ============ DSG (signing) ============

// DSGState holds one party's state for a DKLs23 distributed signing session.
//
// A DSGState is not safe for concurrent use and must be released with Free.
type DSGState struct {
	ptr C.DsgState
}

// NewDSGState creates a signing state from a keyshare. derivationPath is a
// BIP32 path such as "m" or "m/44'/60'/0'/0/0"; the signature is produced for
// the child key at that path.
func NewDSGState(keyshareJSON, derivationPath string) (*DSGState, error) {
	cKeyshare := C.CString(keyshareJSON)
	defer C.free(unsafe.Pointer(cKeyshare))

	cPath := C.CString(derivationPath)
	defer C.free(unsafe.Pointer(cPath))

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	state := C.dkls23_dsg_init(cKeyshare, cPath)
	if state == nil {
		return nil, getLastError()
	}
	return &DSGState{ptr: state}, nil
}

// GenerateMsg1 returns this signer's round-1 message, to be broadcast to all
// other signers.
func (s *DSGState) GenerateMsg1() (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callString(func() *C.char { return C.dkls23_dsg_generate_msg1(s.ptr) })
}

// HandleMsg1 consumes the round-1 messages of all other signers and returns a
// JSON array of point-to-point round-2 messages.
func (s *DSGState) HandleMsg1(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callJSON(msgs, func(cMsgs *C.char) *C.char { return C.dkls23_dsg_handle_msg1(s.ptr, cMsgs) })
}

// HandleMsg2 consumes the round-2 messages addressed to this signer and
// returns a JSON array of point-to-point round-3 messages.
func (s *DSGState) HandleMsg2(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callJSON(msgs, func(cMsgs *C.char) *C.char { return C.dkls23_dsg_handle_msg2(s.ptr, cMsgs) })
}

// HandleMsg3 consumes the round-3 messages addressed to this signer and
// returns an opaque, single-use presignature handle as JSON.
func (s *DSGState) HandleMsg3(msgs []interface{}) (string, error) {
	if s == nil || s.ptr == nil {
		return "", ErrNilState
	}
	return callJSON(msgs, func(cMsgs *C.char) *C.char { return C.dkls23_dsg_handle_msg3(s.ptr, cMsgs) })
}

// Free releases the native state. It is safe to call more than once.
func (s *DSGState) Free() {
	if s != nil && s.ptr != nil {
		C.dkls23_dsg_free_state(s.ptr)
		s.ptr = nil
	}
}

// ============ Signatures ============

// CreatePartialSignature consumes a presignature handle and signs messageHash.
// It returns JSON of the form {"partial": ..., "msg4": ...}: "msg4" must be
// sent to the combining party and "partial" kept by it. A presignature can be
// used only once, even if this call fails.
func CreatePartialSignature(presigJSON string, messageHash [32]byte) (string, error) {
	cPresig := C.CString(presigJSON)
	defer C.free(unsafe.Pointer(cPresig))

	cHash := (*C.uchar)(unsafe.Pointer(&messageHash[0]))
	return callString(func() *C.char { return C.dkls23_create_partial_signature(cPresig, cHash) })
}

// CombineSignatures combines this party's partial signature with the "msg4"
// values of all other signers. It returns the 64-byte signature r || s as a
// hex string, with s normalized to the lower half of the curve order.
func CombineSignatures(partialSigJSON string, msg4List []interface{}) (string, error) {
	cMsg4, err := cJSON(msg4List)
	if err != nil {
		return "", err
	}
	defer C.free(unsafe.Pointer(cMsg4))

	cPartial := C.CString(partialSigJSON)
	defer C.free(unsafe.Pointer(cPartial))

	return callString(func() *C.char { return C.dkls23_combine_signatures(cPartial, cMsg4) })
}

// ============ Key derivation ============

// DerivePublicKey derives the BIP32 child public key at derivationPath. It
// returns JSON of the form {"derived_public_key": "<hex compressed key>"}; use
// DeriveChildPublicKey to get the hex key directly.
func DerivePublicKey(keyshareJSON, derivationPath string) (string, error) {
	cKeyshare := C.CString(keyshareJSON)
	defer C.free(unsafe.Pointer(cKeyshare))

	cPath := C.CString(derivationPath)
	defer C.free(unsafe.Pointer(cPath))

	return callString(func() *C.char { return C.dkls23_derive_public_key(cKeyshare, cPath) })
}

// DeriveChildPublicKey derives the BIP32 child public key at derivationPath
// and returns it as a hex-encoded 33-byte compressed key.
func DeriveChildPublicKey(keyshareJSON, derivationPath string) (string, error) {
	res, err := DerivePublicKey(keyshareJSON, derivationPath)
	if err != nil {
		return "", err
	}
	var out struct {
		Key string `json:"derived_public_key"`
	}
	if err := json.Unmarshal([]byte(res), &out); err != nil {
		return "", errors.New("dkls23: malformed derive_public_key response")
	}
	if out.Key == "" {
		return "", errors.New("dkls23: derive_public_key response has no key")
	}
	return out.Key, nil
}

// DeriveKeyshare derives the keyshare for the BIP32 child at derivationPath.
// The returned keyshare signs for the child key when used with path "m".
func DeriveKeyshare(keyshareJSON, derivationPath string) (string, error) {
	cKeyshare := C.CString(keyshareJSON)
	defer C.free(unsafe.Pointer(cKeyshare))

	cPath := C.CString(derivationPath)
	defer C.free(unsafe.Pointer(cPath))

	return callString(func() *C.char { return C.dkls23_derive_keyshare(cKeyshare, cPath) })
}
