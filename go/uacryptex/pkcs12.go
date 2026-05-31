package uacryptex

import "github.com/itcrow/uacryptex/uacryptex/internal/native"

// Keystore is an opened PKCS#12 container with a selected private key.
type Keystore struct {
	handle *native.Handle
}

// OpenPKCS12 opens a PKCS#12 keystore and selects the first available private key.
func OpenPKCS12(p12 []byte, password string) (*Keystore, error) {
	h, err := native.PKCS12Open(p12, password)
	if err != nil {
		return nil, fromNative(err)
	}
	return &Keystore{handle: h}, nil
}

// Close releases native resources.
func (k *Keystore) Close() {
	if k == nil || k.handle == nil {
		return
	}
	k.handle.Close()
	k.handle = nil
}

// SetCertificate attaches an external X.509 certificate to the store.
func (k *Keystore) SetCertificate(cert []byte) error {
	if k == nil || k.handle == nil {
		return ErrInvalidParam
	}
	return fromNative(k.handle.SetCertificate(cert))
}

// PrivateKey returns a view of the selected private key in this keystore.
// The returned key shares the native handle; close the keystore only after done signing.
func (k *Keystore) PrivateKey() *PrivateKey {
	if k == nil || k.handle == nil {
		return nil
	}
	return &PrivateKey{handle: k.handle}
}
