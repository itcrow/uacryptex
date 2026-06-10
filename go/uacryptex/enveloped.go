package uacryptex

// ContentCipher selects the CMS EnvelopedData content encryption algorithm.
// Key agreement remains DSTU4145 DH + GOST28147-Wrap in all cases.
type ContentCipher int32

const (
	// ContentCipherGost28147CFB is the default (Cryptonite-compatible) GOST 28147-CFB.
	ContentCipherGost28147CFB ContentCipher = 0
	// ContentCipherKalyna256GCM uses DSTU 7624 Kalyna-256/256-GMAC-256 (AEAD GCM).
	ContentCipherKalyna256GCM ContentCipher = 1
	// ContentCipherKalyna128GCM uses DSTU 7624 Kalyna-128/128-GMAC-128 (AEAD GCM).
	ContentCipherKalyna128GCM ContentCipher = 2
	// ContentCipherKalyna512GCM uses DSTU 7624 Kalyna-512/512-GMAC-512 (AEAD GCM).
	ContentCipherKalyna512GCM ContentCipher = 3
)

// EnvelopCMS encrypts data for recipientCert using originatorKey (GOST28147-CFB by default).
// Returns PKCS#7 ContentInfo DER wrapping EnvelopedData.
func EnvelopCMS(data []byte, originatorKey *PrivateKey, recipientCert []byte) ([]byte, error) {
	return EnvelopCMSWithCipher(data, originatorKey, recipientCert, ContentCipherGost28147CFB)
}

// EnvelopCMSWithCipher encrypts data with the selected content cipher.
func EnvelopCMSWithCipher(
	data []byte,
	originatorKey *PrivateKey,
	recipientCert []byte,
	cipher ContentCipher,
) ([]byte, error) {
	if originatorKey == nil || originatorKey.handle == nil {
		return nil, ErrInvalidParam
	}
	if len(recipientCert) == 0 {
		return nil, ErrInvalidParam
	}
	cms, err := originatorKey.handle.CMSEnvelopEncryptWithCipher(data, recipientCert, int32(cipher))
	return cms, fromNative(err)
}

// DecryptCMS decrypts PKCS#7 EnvelopedData using recipientKey and recipientCert.
//
// Pass nil originatorCert when the originator certificate is embedded in the CMS.
// Pass nil external when ciphertext is embedded in the structure.
// The content cipher is read from the CMS (GOST28147-CFB or Kalyna-GCM).
func DecryptCMS(cms []byte, recipientKey *PrivateKey, recipientCert []byte, originatorCert, external []byte) ([]byte, error) {
	if recipientKey == nil || recipientKey.handle == nil {
		return nil, ErrInvalidParam
	}
	if len(recipientCert) == 0 || len(cms) == 0 {
		return nil, ErrInvalidParam
	}
	plain, err := recipientKey.handle.CMSEnvelopDecrypt(cms, external, originatorCert, recipientCert)
	return plain, fromNative(err)
}
