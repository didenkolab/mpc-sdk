package frost

import "errors"

// Errors returned by the FROST bindings. Errors reported by the native
// library wrap ErrFFICall.
var (
	ErrInvalidPartyID   = errors.New("frost: invalid party ID")
	ErrInvalidThreshold = errors.New("frost: invalid threshold")
	ErrFFICall          = errors.New("frost: FFI call failed")
	ErrNilState         = errors.New("frost: state is nil or already freed")
	ErrEmptyMessage     = errors.New("frost: message must not be empty")
)
