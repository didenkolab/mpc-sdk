package dkls23

import "errors"

// Sentinel errors returned by input validation. Errors reported by the native
// library are returned as plain errors prefixed with "dkls23: ".
var (
	ErrNilState         = errors.New("dkls23: state is nil or already freed")
	ErrInvalidPartyID   = errors.New("dkls23: invalid party ID or party count")
	ErrInvalidThreshold = errors.New("dkls23: invalid threshold")
	ErrInvalidRanks     = errors.New("dkls23: invalid ranks")
	ErrFFICall          = errors.New("dkls23: FFI call failed")
)
