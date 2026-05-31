package uacryptex

import (
	"errors"
	"fmt"
)

var (
	// ErrMemory is returned when native allocation fails (RET_MEMORY_ALLOC_ERROR).
	ErrMemory = errors.New("uacryptex: memory allocation failed")

	// ErrInvalidParam is returned for invalid arguments (RET_INVALID_PARAM).
	ErrInvalidParam = errors.New("uacryptex: invalid parameter")

	// ErrVerifyFailed is returned when signature or CMS verification fails.
	ErrVerifyFailed = errors.New("uacryptex: verification failed")

	// ErrUnsupported is returned for not-yet-implemented operations.
	ErrUnsupported = errors.New("uacryptex: unsupported operation")
)

const (
	retOK           int32 = 0
	retMemory       int32 = 1
	retInvalidParam int32 = 2
	retVerifyFailed int32 = 3
)

// Error represents a uacryptex failure with an optional native code.
type Error struct {
	Code    int32
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("uacryptex: error code %d", e.Code)
	}
	return "uacryptex: " + e.Message
}

// mapNativeError converts an FFI status code and message to a Go error.
func mapNativeError(code int32, msg string) error {
	if code == retOK {
		return nil
	}
	switch code {
	case retMemory:
		return ErrMemory
	case retInvalidParam:
		return ErrInvalidParam
	case retVerifyFailed:
		return ErrVerifyFailed
	default:
		return &Error{Code: code, Message: msg}
	}
}
