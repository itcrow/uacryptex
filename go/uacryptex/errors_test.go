package uacryptex

import (
	"errors"
	"testing"
)

func TestMapNativeError(t *testing.T) {
	tests := []struct {
		name string
		code int32
		msg  string
		want error
	}{
		{name: "ok", code: 0, msg: "", want: nil},
		{name: "memory", code: 1, msg: "oom", want: ErrMemory},
		{name: "invalid param", code: 2, msg: "bad arg", want: ErrInvalidParam},
		{name: "verify failed", code: 3, msg: "bad sig", want: ErrVerifyFailed},
		{
			name: "unknown",
			code: 0x0105,
			msg:  "not found",
			want: &Error{Code: 0x0105, Message: "not found"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapNativeError(tt.code, tt.msg)
			if !errors.Is(got, tt.want) && got != tt.want {
				if wantErr, ok := tt.want.(*Error); ok {
					gotErr, ok := got.(*Error)
					if !ok || gotErr.Code != wantErr.Code || gotErr.Message != wantErr.Message {
						t.Fatalf("mapNativeError(%d, %q) = %v, want %v", tt.code, tt.msg, got, tt.want)
					}
					return
				}
				t.Fatalf("mapNativeError(%d, %q) = %v, want %v", tt.code, tt.msg, got, tt.want)
			}
		})
	}
}
