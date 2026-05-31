#ifndef UACRYPTEX_H
#define UACRYPTEX_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Opaque handle for keys, PKCS#12 sessions, etc.
 */
typedef struct UacryptexHandle UacryptexHandle;

/**
 * Byte buffer owned by Rust; freed via [`uacryptex_buf_free`].
 */
typedef struct UacryptexBuf {
  uint8_t *ptr;
  uintptr_t len;
} UacryptexBuf;

/**
 * FFI error payload.
 */
typedef struct UacryptexError {
  int32_t code;
  char message[256];
} UacryptexError;

void uacryptex_handle_free(struct UacryptexHandle *handle);

void uacryptex_buf_free(struct UacryptexBuf buf);

/**
 * Verify certificate signature using issuer certificate.
 */
int32_t uacryptex_cert_verify(const uint8_t *cert,
                              uintptr_t cert_len,
                              const uint8_t *issuer_cert,
                              uintptr_t issuer_cert_len,
                              struct UacryptexError *err);

/**
 * Check notBefore/notAfter at `unix_secs` (0 = now).
 */
int32_t uacryptex_cert_check_validity(const uint8_t *cert,
                                      uintptr_t cert_len,
                                      int64_t unix_secs,
                                      struct UacryptexError *err);

/**
 * Return SubjectPublicKeyInfo DER from certificate.
 */
int32_t uacryptex_cert_spki(const uint8_t *cert,
                            uintptr_t cert_len,
                            struct UacryptexBuf *out,
                            struct UacryptexError *err);

/**
 * Issue an X.509 certificate from PKCS#10 CSR using CA (or self-signed) key handle.
 */
int32_t uacryptex_cert_generate(struct UacryptexHandle *ca_key,
                                const uint8_t *csr,
                                uintptr_t csr_len,
                                uint8_t version,
                                const uint8_t *serial,
                                uintptr_t serial_len,
                                int64_t not_before,
                                int64_t not_after,
                                int32_t self_signed,
                                struct UacryptexBuf *out,
                                struct UacryptexError *err);

/**
 * Sign `data` with a private key handle (PKCS#12 or raw key+cert).
 */
int32_t uacryptex_cms_sign(const uint8_t *data,
                           uintptr_t data_len,
                           struct UacryptexHandle *key,
                           struct UacryptexBuf *out,
                           struct UacryptexError *err);

/**
 * Sign `data` and attach a CAdES-T timestamp (BES + id-aa-signatureTimeStampToken).
 */
int32_t uacryptex_cms_sign_cades_t(const uint8_t *data,
                                   uintptr_t data_len,
                                   struct UacryptexHandle *sign_key,
                                   struct UacryptexHandle *tsa_key,
                                   const uint8_t *serial,
                                   uintptr_t serial_len,
                                   int64_t current_time,
                                   const char *policy_oid,
                                   struct UacryptexBuf *out,
                                   struct UacryptexError *err);

/**
 * Sign `data` and attach CAdES-C refs (BES + certificate/revocation references).
 */
int32_t uacryptex_cms_sign_cades_c(const uint8_t *data,
                                   uintptr_t data_len,
                                   struct UacryptexHandle *sign_key,
                                   const uint8_t *ref_cert,
                                   uintptr_t ref_cert_len,
                                   const uint8_t *ref_crl,
                                   uintptr_t ref_crl_len,
                                   struct UacryptexBuf *out,
                                   struct UacryptexError *err);

/**
 * Sign `data` and attach CAdES-X values (BES + certificate/revocation values).
 */
int32_t uacryptex_cms_sign_cades_x(const uint8_t *data,
                                   uintptr_t data_len,
                                   struct UacryptexHandle *sign_key,
                                   const uint8_t *ref_cert,
                                   uintptr_t ref_cert_len,
                                   const uint8_t *ocsp_response,
                                   uintptr_t ocsp_response_len,
                                   struct UacryptexBuf *out,
                                   struct UacryptexError *err);

/**
 * Sign `data` with CAdES-LT (X + validation certificates/CRLs in SignedData).
 */
int32_t uacryptex_cms_sign_cades_lt(const uint8_t *data,
                                    uintptr_t data_len,
                                    struct UacryptexHandle *sign_key,
                                    const uint8_t *ref_cert,
                                    uintptr_t ref_cert_len,
                                    const uint8_t *full_crl,
                                    uintptr_t full_crl_len,
                                    const uint8_t *delta_crl,
                                    uintptr_t delta_crl_len,
                                    const uint8_t *ocsp_response,
                                    uintptr_t ocsp_response_len,
                                    struct UacryptexBuf *out,
                                    struct UacryptexError *err);

/**
 * Sign `data` with CAdES-A (LT + id-aa-ets-archiveTimeStamp).
 */
int32_t uacryptex_cms_sign_cades_a(const uint8_t *data,
                                   uintptr_t data_len,
                                   struct UacryptexHandle *sign_key,
                                   const uint8_t *ref_cert,
                                   uintptr_t ref_cert_len,
                                   const uint8_t *full_crl,
                                   uintptr_t full_crl_len,
                                   const uint8_t *delta_crl,
                                   uintptr_t delta_crl_len,
                                   const uint8_t *ocsp_response,
                                   uintptr_t ocsp_response_len,
                                   struct UacryptexHandle *tsa_key,
                                   const uint8_t *serial,
                                   uintptr_t serial_len,
                                   int64_t current_time,
                                   const char *policy_oid,
                                   struct UacryptexBuf *out,
                                   struct UacryptexError *err);

/**
 * Verify a CMS SignedData signature.
 *
 * When `data_len > 0`, verifies the signature over `data` (detached or matching
 * encapsulated content). When `data_len == 0`, verifies encapsulated content only.
 */
int32_t uacryptex_cms_verify(const uint8_t *data,
                             uintptr_t data_len,
                             const uint8_t *cms,
                             uintptr_t cms_len,
                             struct UacryptexError *err);

/**
 * Verify CRL signature using issuer certificate.
 */
int32_t uacryptex_crl_verify(const uint8_t *crl,
                             uintptr_t crl_len,
                             const uint8_t *issuer_cert,
                             uintptr_t issuer_cert_len,
                             struct UacryptexError *err);

/**
 * Check whether `cert` is revoked by `crl`. Sets `*revoked` to 1 if revoked, 0 if not.
 */
int32_t uacryptex_crl_check_cert(const uint8_t *crl,
                                 uintptr_t crl_len,
                                 const uint8_t *issuer_cert,
                                 uintptr_t issuer_cert_len,
                                 const uint8_t *cert,
                                 uintptr_t cert_len,
                                 int32_t *revoked,
                                 struct UacryptexError *err);

/**
 * Issue a new CRL from a previous CRL using CA key handle.
 *
 * `crl_type`: 0 = delta, 1 = full.
 * `diff_next_update_secs`: if > 0 use `thisUpdate=now` and `nextUpdate=now+diff`; else roll from previous `nextUpdate`.
 * `merge_delta_crl`: optional delta CRL to merge when `crl_type` is full (NULL allowed).
 * `revoke_serial`: optional serial number to add before generate (NULL allowed).
 */
int32_t uacryptex_crl_generate(struct UacryptexHandle *ca_key,
                               const uint8_t *previous_crl,
                               uintptr_t previous_crl_len,
                               int32_t crl_type,
                               int64_t diff_next_update_secs,
                               const uint8_t *merge_delta_crl,
                               uintptr_t merge_delta_crl_len,
                               const uint8_t *revoke_serial,
                               uintptr_t revoke_serial_len,
                               const char *template_name,
                               const char *description,
                               struct UacryptexBuf *out,
                               struct UacryptexError *err);

/**
 * Generate PKCS#10 CSR using private key handle and Cryptonite subject string.
 */
int32_t uacryptex_csr_generate(struct UacryptexHandle *key,
                               const char *subject,
                               const char *dns,
                               const char *email,
                               const char *subject_dir_attr,
                               struct UacryptexBuf *out,
                               struct UacryptexError *err);

/**
 * Verify CSR self-signature using public key embedded in the request.
 */
int32_t uacryptex_csr_verify(const uint8_t *csr, uintptr_t csr_len, struct UacryptexError *err);

/**
 * Hash `data` with GOST3411 (default), optional AlgorithmIdentifier DER, or cert-selected digest.
 */
int32_t uacryptex_digest(const uint8_t *data,
                         uintptr_t data_len,
                         const uint8_t *algorithm_aid,
                         uintptr_t algorithm_aid_len,
                         const uint8_t *cert,
                         uintptr_t cert_len,
                         struct UacryptexBuf *out,
                         struct UacryptexError *err);

/**
 * Verify a DSTU 4145 signature over GF(2^m) in polynomial basis.
 *
 * Octet encoding (Cryptonite-compatible):
 * - `b`, `n`, `gx`, `gy`, `qx`, `qy`, `hash`: `ByteArray` from `ba_alloc_from_be_hex_string`
 * - `r`, `s`: `ByteArray` from `ba_alloc_from_le_hex_string`
 *
 * Returns `RET_OK` (0) on success.
 */
int32_t uacryptex_dstu4145_verify_pb(const uint32_t *f,
                                     uintptr_t f_len,
                                     int a,
                                     const uint8_t *b,
                                     uintptr_t b_len,
                                     const uint8_t *n,
                                     uintptr_t n_len,
                                     const uint8_t *gx,
                                     uintptr_t gx_len,
                                     const uint8_t *gy,
                                     uintptr_t gy_len,
                                     const uint8_t *qx,
                                     uintptr_t qx_len,
                                     const uint8_t *qy,
                                     uintptr_t qy_len,
                                     const uint8_t *hash,
                                     uintptr_t hash_len,
                                     const uint8_t *r,
                                     uintptr_t r_len,
                                     const uint8_t *s,
                                     uintptr_t s_len,
                                     struct UacryptexError *err);

/**
 * Build CMS EnvelopedData (PKCS#7 ContentInfo) for `recipient_cert`.
 *
 * `originator_key` must be a DSTU4145 (or ECDSA) private key handle with a matching certificate
 * (via `uacryptex_sign_open` or PKCS#12 with bound cert).
 */
int32_t uacryptex_cms_envelop_encrypt(const uint8_t *data,
                                      uintptr_t data_len,
                                      struct UacryptexHandle *originator_key,
                                      const uint8_t *recipient_cert,
                                      uintptr_t recipient_cert_len,
                                      struct UacryptexBuf *out,
                                      struct UacryptexError *err);

/**
 * Decrypt CMS EnvelopedData.
 *
 * Pass `originator_cert_len == 0` when the originator certificate is embedded in the CMS.
 * Pass `external_len == 0` when ciphertext is embedded in the structure.
 */
int32_t uacryptex_cms_envelop_decrypt(const uint8_t *cms,
                                      uintptr_t cms_len,
                                      const uint8_t *external,
                                      uintptr_t external_len,
                                      const uint8_t *originator_cert,
                                      uintptr_t originator_cert_len,
                                      struct UacryptexHandle *recipient_key,
                                      const uint8_t *recipient_cert,
                                      uintptr_t recipient_cert_len,
                                      struct UacryptexBuf *out,
                                      struct UacryptexError *err);

/**
 * Initialize `err` to success (code 0, empty message).
 *
 * # Safety
 *
 * `err` must be a valid pointer to a writable `UacryptexError`, or null (no-op).
 */
void uacryptex_error_init(struct UacryptexError *err);

/**
 * Build a signed OCSP request for `user_cert` issued by `root_cert`.
 */
int32_t uacryptex_ocsp_request_from_cert(const uint8_t *root_cert,
                                         uintptr_t root_cert_len,
                                         const uint8_t *user_cert,
                                         uintptr_t user_cert_len,
                                         struct UacryptexBuf *out,
                                         struct UacryptexError *err);

/**
 * Build an OCSP request for `user_cert` issued by `root_cert`.
 *
 * When `requestor_key` is non-null, the request is signed (CAdES-style requestor cert chain).
 * When null, produces an unsigned request (same as `uacryptex_ocsp_request_from_cert` when nonce enabled).
 * `ocsp_responder_cert` is optional; include in signed request cert chain when set.
 * `include_nonce`: non-zero adds nonce extension; `nonce` may be NULL (20 zero bytes used).
 */
int32_t uacryptex_ocsp_request_generate(const uint8_t *root_cert,
                                        uintptr_t root_cert_len,
                                        const uint8_t *user_cert,
                                        uintptr_t user_cert_len,
                                        struct UacryptexHandle *requestor_key,
                                        const uint8_t *ocsp_responder_cert,
                                        uintptr_t ocsp_responder_cert_len,
                                        const uint8_t *nonce,
                                        uintptr_t nonce_len,
                                        int32_t include_nonce,
                                        struct UacryptexBuf *out,
                                        struct UacryptexError *err);

/**
 * Verify signed OCSP request using requestor certificate.
 */
int32_t uacryptex_ocsp_request_verify(const uint8_t *request,
                                      uintptr_t request_len,
                                      const uint8_t *requestor_cert,
                                      uintptr_t requestor_cert_len,
                                      struct UacryptexError *err);

/**
 * Verify OCSP response signature using OCSP responder certificate.
 */
int32_t uacryptex_ocsp_response_verify(const uint8_t *response,
                                       uintptr_t response_len,
                                       const uint8_t *ocsp_responder_cert,
                                       uintptr_t ocsp_responder_cert_len,
                                       struct UacryptexError *err);

/**
 * Validate OCSP response freshness and singleResponse nextUpdate (`OcspRequestEngine::validate_response`).
 */
int32_t uacryptex_ocsp_response_validate(const uint8_t *request,
                                         uintptr_t request_len,
                                         const uint8_t *response,
                                         uintptr_t response_len,
                                         const uint8_t *root_cert,
                                         uintptr_t root_cert_len,
                                         int64_t current_time,
                                         int32_t timeout_minutes,
                                         struct UacryptexError *err);

/**
 * Generate OCSP response for a signed request (responder key handle + CRLs).
 */
int32_t uacryptex_ocsp_response_generate(const uint8_t *request,
                                         uintptr_t request_len,
                                         const uint8_t *root_cert,
                                         uintptr_t root_cert_len,
                                         const uint8_t *user_cert,
                                         uintptr_t user_cert_len,
                                         const uint8_t *full_crl,
                                         uintptr_t full_crl_len,
                                         const uint8_t *delta_crl,
                                         uintptr_t delta_crl_len,
                                         struct UacryptexHandle *ocsp_key,
                                         int64_t current_time,
                                         struct UacryptexBuf *out,
                                         struct UacryptexError *err);

/**
 * Open a PKCS#12 container and select the first available private key.
 *
 * Returns `RET_OK` (0) on success; `*store` receives an opaque handle freed via
 * [`uacryptex_handle_free`].
 */
int32_t uacryptex_pkcs12_open(const uint8_t *data,
                              uintptr_t data_len,
                              const char *password,
                              struct UacryptexHandle **store,
                              struct UacryptexError *err);

/**
 * Attach an external X.509 certificate to a PKCS#12 store (Cryptonite `pkcs12_set_certificates`).
 *
 * May be called multiple times. Required for some containers (e.g. IIT test PFX) where keys
 * are stored without matching certificate bags.
 */
int32_t uacryptex_pkcs12_set_certificates(struct UacryptexHandle *store,
                                          const uint8_t *cert,
                                          uintptr_t cert_len,
                                          struct UacryptexError *err);

/**
 * Return the number of X.509 certificates stored in the PKCS#12 container.
 */
int32_t uacryptex_pkcs12_certificate_count(struct UacryptexHandle *store,
                                           uintptr_t *count,
                                           struct UacryptexError *err);

/**
 * Copy certificate at `index` (0 .. count-1) from PKCS#12 into `out`.
 */
int32_t uacryptex_pkcs12_get_certificate(struct UacryptexHandle *store,
                                         uintptr_t index,
                                         struct UacryptexBuf *out,
                                         struct UacryptexError *err);

/**
 * Open a signing handle from PKCS#8 PrivateKeyInfo DER and optional matching certificate.
 */
int32_t uacryptex_pkcs8_open(const uint8_t *der,
                             uintptr_t der_len,
                             const uint8_t *cert,
                             uintptr_t cert_len,
                             struct UacryptexHandle **out,
                             struct UacryptexError *err);

/**
 * Open a signing handle from raw private key bytes and an X.509 certificate.
 */
int32_t uacryptex_sign_open(const uint8_t *key,
                            uintptr_t key_len,
                            const uint8_t *cert,
                            uintptr_t cert_len,
                            struct UacryptexHandle **out,
                            struct UacryptexError *err);

/**
 * Sign a precomputed digest (`SignAdapter::sign_hash`).
 */
int32_t uacryptex_sign_hash(const uint8_t *hash,
                            uintptr_t hash_len,
                            struct UacryptexHandle *key,
                            struct UacryptexBuf *out,
                            struct UacryptexError *err);

/**
 * Sign raw data (hash-then-sign inside adapter).
 */
int32_t uacryptex_sign_data(const uint8_t *data,
                            uintptr_t data_len,
                            struct UacryptexHandle *key,
                            struct UacryptexBuf *out,
                            struct UacryptexError *err);

/**
 * Alias for [`uacryptex_sign_hash`] (FFI.md Phase 1).
 */
int32_t uacryptex_dstu4145_sign(const uint8_t *hash,
                                uintptr_t hash_len,
                                struct UacryptexHandle *key,
                                struct UacryptexBuf *out,
                                struct UacryptexError *err);

/**
 * Build TSP request from raw data (GOST3411 hash of `data`).
 */
int32_t uacryptex_tsp_request_from_data(const uint8_t *data,
                                        uintptr_t data_len,
                                        const char *policy_oid,
                                        int32_t cert_req,
                                        struct UacryptexBuf *out,
                                        struct UacryptexError *err);

/**
 * Build TSP request from precomputed GOST3411 digest.
 */
int32_t uacryptex_tsp_request_from_hash(const uint8_t *hash,
                                        uintptr_t hash_len,
                                        const char *policy_oid,
                                        int32_t cert_req,
                                        struct UacryptexBuf *out,
                                        struct UacryptexError *err);

/**
 * Verify TSP response token signature using TSA certificate.
 */
int32_t uacryptex_tsp_response_verify(const uint8_t *response,
                                      uintptr_t response_len,
                                      const uint8_t *tsa_cert,
                                      uintptr_t tsa_cert_len,
                                      struct UacryptexError *err);

/**
 * Generate TSP response for `request` using TSA private key handle.
 */
int32_t uacryptex_tsp_response_generate(const uint8_t *request,
                                        uintptr_t request_len,
                                        struct UacryptexHandle *key,
                                        const uint8_t *serial,
                                        uintptr_t serial_len,
                                        int64_t current_time,
                                        struct UacryptexBuf *out,
                                        struct UacryptexError *err);

/**
 * Verify a detached signature over a precomputed digest.
 */
int32_t uacryptex_verify_hash(const uint8_t *digest,
                              uintptr_t digest_len,
                              const uint8_t *signature,
                              uintptr_t signature_len,
                              const uint8_t *cert,
                              uintptr_t cert_len,
                              struct UacryptexError *err);

/**
 * Verify a detached signature over raw data (hash-then-verify inside adapter).
 */
int32_t uacryptex_verify_data(const uint8_t *data,
                              uintptr_t data_len,
                              const uint8_t *signature,
                              uintptr_t signature_len,
                              const uint8_t *cert,
                              uintptr_t cert_len,
                              struct UacryptexError *err);

/**
 * Alias for [`uacryptex_verify_hash`] (FFI.md Phase 1).
 */
int32_t uacryptex_dstu4145_verify(const uint8_t *digest,
                                  uintptr_t digest_len,
                                  const uint8_t *signature,
                                  uintptr_t signature_len,
                                  const uint8_t *cert,
                                  uintptr_t cert_len,
                                  struct UacryptexError *err);

int32_t uacryptex_version(char *out, uintptr_t cap);

#endif  /* UACRYPTEX_H */
