package uacryptex

import (
	"errors"

	"github.com/itcrow/uacryptex/uacryptex/internal/native"
)

func fromNative(err error) error {
	if err == nil {
		return nil
	}
	var ne *native.NativeError
	if errors.As(err, &ne) {
		return mapNativeError(ne.Code, ne.Message)
	}
	return err
}
