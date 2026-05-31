<?php

declare(strict_types=1);

namespace Itcrow\Uacryptex;

final class Native
{
    private const RET_OK = 0;
    private const RET_MEMORY = 1;
    private const RET_INVALID_PARAM = 2;
    private const RET_VERIFY_FAILED = 3;

    private static ?\FFI $ffi = null;

    public static function ffi(): \FFI
    {
        if (self::$ffi === null) {
            $header = file_get_contents(self::headerPath());
            if ($header === false) {
                throw new UacryptexError('cannot read uacryptex.h');
            }
            self::$ffi = \FFI::cdef($header, self::libPath());
        }

        return self::$ffi;
    }

    public static function libPath(): string
    {
        $env = getenv('UACRYPTEX_LIB');
        if ($env !== false && $env !== '') {
            return $env;
        }

        $os = PHP_OS_FAMILY === 'Windows' ? 'windows' : (PHP_OS_FAMILY === 'Darwin' ? 'darwin' : 'linux');
        $arch = str_contains(PHP_UNAME('m'), 'arm') || str_contains(PHP_UNAME('m'), 'aarch') ? 'arm64' : 'amd64';
        $name = match ($os) {
            'windows' => 'uacryptex_ffi.dll',
            'darwin' => 'libuacryptex_ffi.dylib',
            default => 'libuacryptex_ffi.so',
        };

        $rel = "/native/lib/{$os}/{$arch}/shared/{$name}";
        $roots = [
            dirname(__DIR__) . $rel,
            dirname(__DIR__, 2) . $rel,
        ];

        foreach ($roots as $path) {
            if (is_file($path)) {
                return $path;
            }
        }

        throw new UacryptexError(
            'native library not found (tried: ' . implode(', ', $roots) . '). '
            . 'Run ./scripts/build-ffi.sh && ./scripts/sync-native-libs.sh or set UACRYPTEX_LIB.'
        );
    }

    public static function headerPath(): string
    {
        return dirname(__DIR__, 2) . '/include/uacryptex.h';
    }

    public static function version(): string
    {
        $ffi = self::ffi();
        $buf = $ffi->new('char[64]');
        $rc = $ffi->uacryptex_version($buf, 64);
        if ($rc !== self::RET_OK) {
            throw new UacryptexError("uacryptex_version failed with code {$rc}", (int) $rc);
        }

        return \FFI::string($buf);
    }

    /** @return \FFI\CData UacryptexHandle* */
    public static function signOpen(string $key, string $cert): \FFI\CData
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexHandle*');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_sign_open($key, strlen($key), $cert, strlen($cert), \FFI::addr($out), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);

        return $out[0];
    }

    /** @return \FFI\CData UacryptexHandle* */
    public static function pkcs12Open(string $data, string $password): \FFI\CData
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexHandle*');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_pkcs12_open($data, strlen($data), $password, \FFI::addr($out), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);

        return $out[0];
    }

    public static function handleFree(?\FFI\CData $handle): void
    {
        if ($handle === null) {
            return;
        }
        self::ffi()->uacryptex_handle_free($handle);
    }

    public static function setCertificate(\FFI\CData $handle, string $cert): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_pkcs12_set_certificates($handle, $cert, strlen($cert), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);
    }

    public static function signHash(\FFI\CData $handle, string $digest): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_sign_hash($digest, strlen($digest), $handle, \FFI::addr($out), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function cmsSign(\FFI\CData $handle, string $data): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cms_sign($data, strlen($data), $handle, \FFI::addr($out), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function cmsSignCadesT(
        \FFI\CData $signKey,
        \FFI\CData $tsaKey,
        string $data,
        string $serial,
        int $currentTime,
        ?string $policyOid = null,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $policy = $policyOid ?? '';
        $rc = $ffi->uacryptex_cms_sign_cades_t(
            $data,
            strlen($data),
            $signKey,
            $tsaKey,
            $serial,
            strlen($serial),
            $currentTime,
            $policy !== '' ? $policy : null,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function cmsSignCadesC(
        \FFI\CData $signKey,
        string $data,
        string $refCert,
        string $refCrl,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cms_sign_cades_c(
            $data,
            strlen($data),
            $signKey,
            $refCert,
            strlen($refCert),
            $refCrl,
            strlen($refCrl),
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function cmsSignCadesX(
        \FFI\CData $signKey,
        string $data,
        string $refCert,
        string $ocspResponse,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cms_sign_cades_x(
            $data,
            strlen($data),
            $signKey,
            $refCert,
            strlen($refCert),
            $ocspResponse,
            strlen($ocspResponse),
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function cmsSignCadesLt(
        \FFI\CData $signKey,
        string $data,
        string $refCert,
        string $fullCrl,
        string $ocspResponse,
        string $deltaCrl = '',
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cms_sign_cades_lt(
            $data,
            strlen($data),
            $signKey,
            $refCert,
            strlen($refCert),
            $fullCrl,
            strlen($fullCrl),
            $deltaCrl,
            strlen($deltaCrl),
            $ocspResponse,
            strlen($ocspResponse),
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function cmsSignCadesA(
        \FFI\CData $signKey,
        \FFI\CData $tsaKey,
        string $data,
        string $refCert,
        string $fullCrl,
        string $ocspResponse,
        string $serial,
        int $currentTime,
        string $deltaCrl = '',
        ?string $policyOid = null,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $policy = $policyOid ?? '';
        $rc = $ffi->uacryptex_cms_sign_cades_a(
            $data,
            strlen($data),
            $signKey,
            $refCert,
            strlen($refCert),
            $fullCrl,
            strlen($fullCrl),
            $deltaCrl,
            strlen($deltaCrl),
            $ocspResponse,
            strlen($ocspResponse),
            $tsaKey,
            $serial,
            strlen($serial),
            $currentTime,
            $policy !== '' ? $policy : null,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function cmsVerify(string $data, string $cms): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cms_verify($data, strlen($data), $cms, strlen($cms), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);
    }

    public static function cmsEnvelopEncrypt(\FFI\CData $handle, string $data, string $recipientCert): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cms_envelop_encrypt(
            $data,
            strlen($data),
            $handle,
            $recipientCert,
            strlen($recipientCert),
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function cmsEnvelopDecrypt(
        \FFI\CData $handle,
        string $cms,
        ?string $external,
        ?string $originatorCert,
        string $recipientCert,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $ext = $external ?? '';
        $orig = $originatorCert ?? '';
        $rc = $ffi->uacryptex_cms_envelop_decrypt(
            $cms,
            strlen($cms),
            $ext,
            strlen($ext),
            $orig,
            strlen($orig),
            $handle,
            $recipientCert,
            strlen($recipientCert),
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function digest(string $data, ?string $algorithmAid = null, ?string $cert = null): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $aid = $algorithmAid ?? '';
        $certDer = $cert ?? '';
        $rc = $ffi->uacryptex_digest(
            $data,
            strlen($data),
            $aid,
            strlen($aid),
            $certDer,
            strlen($certDer),
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    /** @return \FFI\CData UacryptexHandle* */
    public static function pkcs8Open(string $der, ?string $cert = null): \FFI\CData
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexHandle*');
        $err = self::initError($ffi);
        $certDer = $cert ?? '';
        $rc = $ffi->uacryptex_pkcs8_open(
            $der,
            strlen($der),
            $certDer,
            strlen($certDer),
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return $out[0];
    }

    public static function signData(\FFI\CData $handle, string $data): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_sign_data($data, strlen($data), $handle, \FFI::addr($out), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function verifyHash(string $digest, string $signature, string $cert): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_verify_hash(
            $digest,
            strlen($digest),
            $signature,
            strlen($signature),
            $cert,
            strlen($cert),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);
    }

    public static function verifyData(string $data, string $signature, string $cert): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_verify_data(
            $data,
            strlen($data),
            $signature,
            strlen($signature),
            $cert,
            strlen($cert),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);
    }

    public static function certVerify(string $cert, string $issuerCert): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cert_verify(
            $cert,
            strlen($cert),
            $issuerCert,
            strlen($issuerCert),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);
    }

    public static function certCheckValidity(string $cert, int $unixSecs = 0): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cert_check_validity($cert, strlen($cert), $unixSecs, \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);
    }

    public static function certSpki(string $cert): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cert_spki($cert, strlen($cert), \FFI::addr($out), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function crlVerify(string $crl, string $issuerCert): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_crl_verify(
            $crl,
            strlen($crl),
            $issuerCert,
            strlen($issuerCert),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);
    }

    public static function crlCheckCert(string $crl, string $issuerCert, string $cert): bool
    {
        $ffi = self::ffi();
        $revoked = $ffi->new('int32_t');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_crl_check_cert(
            $crl,
            strlen($crl),
            $issuerCert,
            strlen($issuerCert),
            $cert,
            strlen($cert),
            \FFI::addr($revoked),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return (int) $revoked->cdata !== 0;
    }

    public static function pkcs12CertificateCount(\FFI\CData $handle): int
    {
        $ffi = self::ffi();
        $count = $ffi->new('uintptr_t');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_pkcs12_certificate_count($handle, \FFI::addr($count), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);

        return (int) $count->cdata;
    }

    public static function pkcs12GetCertificate(\FFI\CData $handle, int $index): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_pkcs12_get_certificate($handle, $index, \FFI::addr($out), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function ocspRequestFromCert(string $rootCert, string $userCert): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_ocsp_request_from_cert(
            $rootCert,
            strlen($rootCert),
            $userCert,
            strlen($userCert),
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function ocspRequestGenerate(
        string $rootCert,
        string $userCert,
        ?\FFI\CData $requestorKey = null,
        ?string $ocspResponderCert = null,
        ?string $nonce = null,
        bool $includeNonce = true,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_ocsp_request_generate(
            $rootCert,
            strlen($rootCert),
            $userCert,
            strlen($userCert),
            $requestorKey,
            $ocspResponderCert ?? '',
            $ocspResponderCert !== null ? strlen($ocspResponderCert) : 0,
            $nonce ?? '',
            $nonce !== null ? strlen($nonce) : 0,
            $includeNonce ? 1 : 0,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function ocspResponseVerify(string $response, string $ocspResponderCert): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_ocsp_response_verify(
            $response,
            strlen($response),
            $ocspResponderCert,
            strlen($ocspResponderCert),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);
    }

    public static function ocspResponseValidate(
        string $request,
        string $response,
        string $rootCert,
        int $currentTime,
        int $timeoutMinutes,
    ): void {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_ocsp_response_validate(
            $request,
            strlen($request),
            $response,
            strlen($response),
            $rootCert,
            strlen($rootCert),
            $currentTime,
            $timeoutMinutes,
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);
    }

    public static function ocspResponseGenerate(
        \FFI\CData $ocspKey,
        string $request,
        string $rootCert,
        string $userCert,
        string $fullCrl,
        string $deltaCrl,
        int $currentTime,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_ocsp_response_generate(
            $request,
            strlen($request),
            $rootCert,
            strlen($rootCert),
            $userCert,
            strlen($userCert),
            $fullCrl,
            strlen($fullCrl),
            $deltaCrl,
            strlen($deltaCrl),
            $ocspKey,
            $currentTime,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function tspRequestFromData(string $data, ?string $policyOid = null, bool $certReq = true): string
    {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $policy = $policyOid ?? '';
        $rc = $ffi->uacryptex_tsp_request_from_data(
            $data,
            strlen($data),
            $policy,
            $certReq ? 1 : 0,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function tspResponseVerify(string $response, string $tsaCert): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_tsp_response_verify(
            $response,
            strlen($response),
            $tsaCert,
            strlen($tsaCert),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);
    }

    public static function tspResponseGenerate(
        \FFI\CData $tsaKey,
        string $request,
        string $serial,
        int $currentTime,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_tsp_response_generate(
            $request,
            strlen($request),
            $tsaKey,
            $serial,
            strlen($serial),
            $currentTime,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function csrGenerate(
        \FFI\CData $key,
        string $subject,
        ?string $dns = null,
        ?string $email = null,
        ?string $subjectDirAttr = null,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $dnsStr = $dns ?? '';
        $emailStr = $email ?? '';
        $sdaStr = $subjectDirAttr ?? '';
        $rc = $ffi->uacryptex_csr_generate(
            $key,
            $subject,
            $dnsStr,
            $emailStr,
            $sdaStr,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function csrVerify(string $csr): void
    {
        $ffi = self::ffi();
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_csr_verify($csr, strlen($csr), \FFI::addr($err));
        self::check($ffi, (int) $rc, $err);
    }

    public static function certGenerate(
        \FFI\CData $caKey,
        string $csr,
        int $version,
        string $serial,
        int $notBefore,
        int $notAfter,
        bool $selfSigned,
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_cert_generate(
            $caKey,
            $csr,
            strlen($csr),
            $version,
            $serial,
            strlen($serial),
            $notBefore,
            $notAfter,
            $selfSigned ? 1 : 0,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    public static function crlGenerate(
        \FFI\CData $caKey,
        string $previousCrl,
        int $crlType,
        int $diffNextUpdateSecs,
        ?string $mergeDeltaCrl = null,
        ?string $revokeSerial = null,
        string $templateName = '',
        string $description = '',
    ): string {
        $ffi = self::ffi();
        $out = $ffi->new('UacryptexBuf');
        $err = self::initError($ffi);
        $tmpl = $templateName !== '' ? $templateName : null;
        $desc = $description !== '' ? $description : null;
        $rc = $ffi->uacryptex_crl_generate(
            $caKey,
            $previousCrl,
            strlen($previousCrl),
            $crlType,
            $diffNextUpdateSecs,
            $mergeDeltaCrl ?? '',
            $mergeDeltaCrl !== null ? strlen($mergeDeltaCrl) : 0,
            $revokeSerial ?? '',
            $revokeSerial !== null ? strlen($revokeSerial) : 0,
            $tmpl,
            $desc,
            \FFI::addr($out),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);

        return self::bufToBytes($ffi, $out);
    }

    /**
     * @param list<int> $f
     */
    public static function dstu4145VerifyPb(
        array $f,
        int $a,
        string $b,
        string $n,
        string $gx,
        string $gy,
        string $qx,
        string $qy,
        string $hash,
        string $r,
        string $s,
    ): void {
        $ffi = self::ffi();
        $fArr = $ffi->new('uint32_t[' . count($f) . ']');
        foreach ($f as $i => $value) {
            $fArr[$i] = $value;
        }
        $err = self::initError($ffi);
        $rc = $ffi->uacryptex_dstu4145_verify_pb(
            \FFI::addr($fArr[0]),
            count($f),
            $a,
            $b,
            strlen($b),
            $n,
            strlen($n),
            $gx,
            strlen($gx),
            $gy,
            strlen($gy),
            $qx,
            strlen($qx),
            $qy,
            strlen($qy),
            $hash,
            strlen($hash),
            $r,
            strlen($r),
            $s,
            strlen($s),
            \FFI::addr($err),
        );
        self::check($ffi, (int) $rc, $err);
    }

    private static function initError(\FFI $ffi): \FFI\CData
    {
        $err = $ffi->new('UacryptexError');
        $ffi->uacryptex_error_init(\FFI::addr($err));

        return $err;
    }

    private static function bufToBytes(\FFI $ffi, \FFI\CData $buf): string
    {
        if ($buf->ptr === null || $buf->len === 0) {
            $ffi->uacryptex_buf_free($buf);

            return '';
        }
        $bytes = \FFI::string($buf->ptr, (int) $buf->len);
        $ffi->uacryptex_buf_free($buf);

        return $bytes;
    }

    private static function check(\FFI $ffi, int $code, \FFI\CData $err): void
    {
        if ($code === self::RET_OK) {
            return;
        }
        $msg = \FFI::string($err->message);
        throw match ($code) {
            self::RET_MEMORY => new MemoryError($msg, $code),
            self::RET_INVALID_PARAM => new InvalidParamError($msg, $code),
            self::RET_VERIFY_FAILED => new VerifyFailedError($msg, $code),
            default => new UacryptexError($msg, $code),
        };
    }
}
