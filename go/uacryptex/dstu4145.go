package uacryptex

import "github.com/itcrow/uacryptex/uacryptex/internal/native"

// VerifyDstu4145PB verifies a DSTU 4145 signature over GF(2^m) in polynomial basis.
//
// Octet encoding (Cryptonite-compatible):
//   - b, n, gx, gy, qx, qy, hash: big-endian hex decoded then byte-reversed
//   - r, s: little-endian hex
func VerifyDstu4145PB(f []uint32, a int32, b, n, gx, gy, qx, qy, hash, r, s []byte) error {
	return fromNative(native.Dstu4145VerifyPB(f, a, b, n, gx, gy, qx, qy, hash, r, s))
}
