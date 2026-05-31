#!/usr/bin/env bash
# Generate docs/API_INVENTORY.md from Cryptonite CRYPTONITE_EXPORT headers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRYPTONITE="${ROOT}/../cryptonite/src"
HEADER="${ROOT}/include/uacryptex.h"
OUT="${ROOT}/docs/API_INVENTORY.md"
TMP="$(mktemp)"

# Map FFI entry points to Go public API (Python/PHP/Node use snake_case / camelCase parity).
go_api_for_ffi() {
    case "$1" in
        uacryptex_version) echo "LibraryVersion()" ;;
        uacryptex_error_init) echo "(lifecycle)" ;;
        uacryptex_buf_free) echo "(lifecycle)" ;;
        uacryptex_handle_free) echo "(lifecycle)" ;;
        uacryptex_sign_open) echo "OpenPrivateKey()" ;;
        uacryptex_sign_hash) echo "PrivateKey.SignHash()" ;;
        uacryptex_sign_data) echo "PrivateKey.SignData()" ;;
        uacryptex_dstu4145_sign) echo "PrivateKey.SignHash() (alias)" ;;
        uacryptex_pkcs8_open) echo "OpenPKCS8()" ;;
        uacryptex_pkcs12_open) echo "OpenPKCS12()" ;;
        uacryptex_pkcs12_set_certificates) echo "Keystore.SetCertificate()" ;;
        uacryptex_pkcs12_certificate_count) echo "Keystore.CertificateCount()" ;;
        uacryptex_pkcs12_get_certificate) echo "Keystore.GetCertificate()" ;;
        uacryptex_digest) echo "Digest()" ;;
        uacryptex_verify_hash) echo "VerifyHash()" ;;
        uacryptex_verify_data) echo "VerifyData()" ;;
        uacryptex_dstu4145_verify) echo "VerifyHash() (alias)" ;;
        uacryptex_dstu4145_verify_pb) echo "VerifyDstu4145PB()" ;;
        uacryptex_cert_verify) echo "VerifyCertificate()" ;;
        uacryptex_cert_check_validity) echo "CheckCertificateValidity()" ;;
        uacryptex_cert_spki) echo "CertificateSPKI()" ;;
        uacryptex_cert_generate) echo "PrivateKey.GenerateCertificate()" ;;
        uacryptex_cms_sign) echo "SignCMS()" ;;
        uacryptex_cms_sign_cades_t) echo "SignCmsCadesT()" ;;
        uacryptex_cms_sign_cades_c) echo "SignCmsCadesC()" ;;
        uacryptex_cms_sign_cades_x) echo "SignCmsCadesX()" ;;
        uacryptex_cms_sign_cades_lt) echo "SignCmsCadesLT()" ;;
        uacryptex_cms_sign_cades_a) echo "SignCmsCadesA()" ;;
        uacryptex_cms_verify) echo "VerifyCMS()" ;;
        uacryptex_cms_envelop_encrypt) echo "EnvelopCMS()" ;;
        uacryptex_cms_envelop_decrypt) echo "DecryptCMS()" ;;
        uacryptex_crl_verify) echo "VerifyCRL()" ;;
        uacryptex_crl_check_cert) echo "IsCertificateRevoked()" ;;
        uacryptex_crl_generate) echo "PrivateKey.GenerateCRL()" ;;
        uacryptex_ocsp_request_from_cert) echo "OcspRequestFromCert()" ;;
        uacryptex_ocsp_request_generate) echo "OcspRequestGenerate()" ;;
        uacryptex_ocsp_request_verify) echo "OcspRequestVerify()" ;;
        uacryptex_ocsp_response_verify) echo "OcspResponseVerify()" ;;
        uacryptex_ocsp_response_validate) echo "OcspResponseValidate()" ;;
        uacryptex_ocsp_response_generate) echo "PrivateKey.OcspResponseGenerate()" ;;
        uacryptex_tsp_request_from_data) echo "TspRequestFromData()" ;;
        uacryptex_tsp_request_from_hash) echo "TspRequestFromHash()" ;;
        uacryptex_tsp_response_verify) echo "TspResponseVerify()" ;;
        uacryptex_tsp_response_generate) echo "PrivateKey.TspResponseGenerate()" ;;
        uacryptex_csr_generate) echo "PrivateKey.CsrGenerate()" ;;
        uacryptex_csr_verify) echo "CsrVerify()" ;;
        *) echo "—" ;;
    esac
}

extract_symbol() {
    sed -E 's/^[[:space:]]*CRYPTONITE_EXPORT[[:space:]]+//' "$1" \
        | sed -E 's/[[:space:]]*\(.*$//' \
        | awk '{print $NF}'
}

map_target() {
    local sym="$1"

    case "$sym" in
        get_*_desc|ber_*|der_*|xer_*|uper_*|asn_*|ANY_*|OCTET_*|INTEGER_*|BOOLEAN_*|NULL_*|ENUMERATED_*|Native*|Printable*|UTF8*|UTCTime*|GeneralizedTime*|Visible*|BMP*|T61*|Teletex*|Universal*|Graphic*|Numeric*|IA5*|ObjectDescriptor*|RELATIVE*|REAL_*|BIT_*)
            echo "uacryptex-core::pki (der types)|skip — use der crate" ;;
        pthread_*)
            echo "—|N/A std::sync" ;;
        ba_*|wa_*|prng_*|rs_*|stacktrace_*|error_ctx_*)
            echo "uacryptex-core::util|internal" ;;
        dstu4145_*)
            echo "uacryptex-core::primitives::dstu4145|Phase 1" ;;
        dstu7564_*)
            echo "uacryptex-core::primitives::dstu7564|Phase 1" ;;
        dstu7624_*)
            echo "uacryptex-core::primitives::dstu7624|Phase 1" ;;
        gost28147_*|gost34_311_*|gost3410_*)
            echo "uacryptex-core::primitives::gost|Phase 1" ;;
        aes_*|des_*|sha1_*|sha2_*|md5_*|rsa_*|dsa_*|ecdsa_*|hmac_*|ripemd_*|make_*padding*)
            echo "uacryptex-core::primitives::intl|RustCrypto" ;;
        pkcs8_*|pkcs5_*|pkcs12_*|cert_store_*)
            echo "uacryptex-core::storage|Phase 2" ;;
        ecert_*|ecert_request_*|esigned_*|esigner_*|ecrl_*|eocsp*|etsp*|eenvel_*)
            echo "uacryptex-core::pki::engine|Phase 2" ;;
        cert_*|creq_*|crl_*|signed_*|sinfo_*|spki_*|ocsp_*|tsreq_*|tsresp_*|ext_*|exts_*|aid_*|oids_*|pkix_*|content_info_*|enveloped_*|certification_*)
            echo "uacryptex-core::pki|Phase 2" ;;
        *adapter*|cryptonite_manager|create_*_spki|get_gost28147*|wrap_session_key|unwrap_session_key|adapters_map_*)
            echo "uacryptex-core::pki::crypto|Phase 2" ;;
        uacryptex_*)
            echo "uacryptex-ffi|done" ;;
        *)
            echo "uacryptex-core|TBD" ;;
    esac
}

module_from_path() {
    case "$1" in
        */cryptonite/c/*) echo "cryptonite" ;;
        */asn1/c/*) echo "asn1" ;;
        */pkix/c/*) echo "pkix" ;;
        */storage/c/*) echo "storage" ;;
        */pthread/c/*) echo "pthread" ;;
        *) echo "other" ;;
    esac
}

grep -rh "CRYPTONITE_EXPORT" "$CRYPTONITE" --include="*.h" -H \
    | sed 's/^[[:space:]]*//' \
    > "$TMP"

total=$(awk -F: '{print $2}' "$TMP" | while read -r line; do echo "$line" | sed -E 's/CRYPTONITE_EXPORT[[:space:]]+//' | sed -E 's/[[:space:]]*\(.*$//' | awk '{print $NF}'; done | sort -u | wc -l)

ffi_tmp="$(mktemp)"
grep -E '^int32_t uacryptex_' "$HEADER" 2>/dev/null \
    | sed -E 's/^int32_t (uacryptex_[a-z0-9_]+)\(.*/\1/' \
    | sort -u > "$ffi_tmp" || true
ffi_count=$(wc -l < "$ffi_tmp" | tr -d ' ')

{
    echo "# Cryptonite → uacryptex API inventory"
    echo
    echo "Auto-generated by \`scripts/generate-api-inventory.sh\`. Do not edit manually."
    echo
    echo "Source: \`../cryptonite/src/**/*.h\`"
    echo "Generated: $(date -u +"%Y-%m-%d %H:%M UTC")"
    echo
    echo "## Summary"
    echo
    echo "| Metric | Value |"
    echo "|--------|-------|"
    echo "| Exported symbols (unique) | ${total} |"
    echo "| Stable C ABI entry points | ${ffi_count} |"
    echo "| Go module | \`github.com/itcrow/uacryptex\` |"
    echo "| Header | \`include/uacryptex.h\` |"
    echo
    echo "## Module mapping"
    echo
    echo "| Cryptonite | uacryptex | Strategy |"
    echo "|------------|-----------|----------|"
    echo "| \`cryptonite/\` | \`uacryptex-core::primitives\` | Port UA; intl → RustCrypto |"
    echo "| \`asn1/\` | \`der\` crate | No asn1c port |"
    echo "| \`pkix/\` | \`uacryptex-core::pki\` | Engines + API |"
    echo "| \`storage/\` | \`uacryptex-core::storage\` | PKCS#8/#12 |"
    echo "| \`pthread/\` | — | \`std::sync\` |"
    echo
    echo "## Stable C ABI (\`uacryptex-ffi\`)"
    echo
    echo "Generated from \`include/uacryptex.h\`. Python, PHP, and Node.js bindings mirror the same surface (see [BINDINGS.md](BINDINGS.md))."
    echo
    echo "| FFI | Go (\`go/uacryptex\`) | Bindings |"
    echo "|-----|---------------------|----------|"
    while read -r sym; do
        [[ -z "$sym" ]] && continue
        go_api=$(go_api_for_ffi "$sym")
        echo "| \`${sym}\` | \`${go_api}\` | Go, Python, PHP, Node |"
    done < "$ffi_tmp"
    echo
    echo "### Planned FFI (not yet exported)"
    echo
    echo "| Area | Notes |"
    echo "|------|-------|"
    echo "| CAdES-C/X/LT | \`CompleteCertificateRefs\`, \`CertValues\`, … — needs ESS attribute types in core |"
    echo "| ONB DSTU4145 verify | low-level; PB verify exported as \`uacryptex_dstu4145_verify_pb\` |"
    echo
    echo "## Symbol table"
    echo
    echo "| Symbol | Module | uacryptex target | Phase |"
    echo "|--------|--------|------------------|-------|"

    while IFS= read -r line; do
        file="${line%%:*}"
        rest="${line#*:}"
        sym=$(echo "$rest" | sed -E 's/CRYPTONITE_EXPORT[[:space:]]+//' | sed -E 's/[[:space:]]*\(.*$//' | awk '{print $NF}' | sed 's/^\*//')
        [[ -z "$sym" || "$sym" == "extern" ]] && continue
        mod=$(module_from_path "$file")
        mapping=$(map_target "$sym")
        target=$(echo "$mapping" | cut -d'|' -f1)
        phase=$(echo "$mapping" | cut -d'|' -f2)
        echo "| \`${sym}\` | ${mod} | ${target} | ${phase} |"
    done < "$TMP" | sort -u

} > "$OUT"

rm -f "$TMP" "$ffi_tmp"
echo "Wrote ${OUT} (${total} cryptonite symbols, ${ffi_count} FFI entry points)"
