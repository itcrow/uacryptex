package uacryptex

import (
	"crypto"
	"io"

	"github.com/itcrow/uacryptex/uacryptex/internal/native"
)

// PrivateKey is a private key backed by uacryptex-core (DSTU4145, ECDSA, …).
type PrivateKey struct {
	handle *native.Handle
}

// OpenPrivateKey creates a signing key from raw private key bytes and a DER certificate.
func OpenPrivateKey(key, cert []byte) (*PrivateKey, error) {
	h, err := native.SignOpen(key, cert)
	if err != nil {
		return nil, fromNative(err)
	}
	return &PrivateKey{handle: h}, nil
}

// Close releases native resources.
func (k *PrivateKey) Close() {
	if k == nil || k.handle == nil {
		return
	}
	k.handle.Close()
	k.handle = nil
}

// nativeHandle exposes the underlying handle for CMS and keystore operations.
func (k *PrivateKey) nativeHandle() *native.Handle {
	if k == nil {
		return nil
	}
	return k.handle
}

// Public returns the public key. Not yet exposed for DSTU4145 keys.
func (k *PrivateKey) Public() crypto.PublicKey {
	return nil
}

// Sign signs digest with opts. The caller must pass an already-hashed digest
// (see crypto.Signer). For DSTU4145 keys the digest must be 32 bytes (GOST3411).
func (k *PrivateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	sig, err := k.handle.SignHash(digest)
	return sig, fromNative(err)
}

// SignHash signs a precomputed digest without going through crypto.Signer.
func (k *PrivateKey) SignHash(digest []byte) ([]byte, error) {
	if k == nil || k.handle == nil {
		return nil, ErrInvalidParam
	}
	sig, err := k.handle.SignHash(digest)
	return sig, fromNative(err)
}

// Ensure PrivateKey implements crypto.Signer.
var _ crypto.Signer = (*PrivateKey)(nil)
