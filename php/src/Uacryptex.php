<?php

declare(strict_types=1);

namespace Itcrow\Uacryptex;

final class Uacryptex
{
    public const VERSION = '0.1.0';

    public static function libraryVersion(): string
    {
        return Native::version();
    }

    public static function openPrivateKey(string $key, string $cert): PrivateKey
    {
        return new PrivateKey(Native::signOpen($key, $cert));
    }

    public static function openPkcs12(string $data, string $password): Keystore
    {
        return new Keystore(Native::pkcs12Open($data, $password));
    }

    public static function openPkcs8(string $der, ?string $cert = null): PrivateKey
    {
        return new PrivateKey(Native::pkcs8Open($der, $cert));
    }

    public static function digest(string $data, ?string $algorithmAid = null, ?string $cert = null): string
    {
        return Native::digest($data, $algorithmAid, $cert);
    }

    public static function signData(string $data, PrivateKey $key): string
    {
        return Native::signData($key->nativeHandle(), $data);
    }

    public static function verifyHash(string $digest, string $signature, string $cert): void
    {
        Native::verifyHash($digest, $signature, $cert);
    }

    public static function verifyData(string $data, string $signature, string $cert): void
    {
        Native::verifyData($data, $signature, $cert);
    }

    public static function verifyCertificate(string $cert, string $issuerCert): void
    {
        Native::certVerify($cert, $issuerCert);
    }

    public static function checkCertificateValidity(string $cert, int $unixSecs = 0): void
    {
        Native::certCheckValidity($cert, $unixSecs);
    }

    public static function certificateSpki(string $cert): string
    {
        return Native::certSpki($cert);
    }

    public static function verifyCrl(string $crl, string $issuerCert): void
    {
        Native::crlVerify($crl, $issuerCert);
    }

    public static function isCertificateRevoked(string $crl, string $issuerCert, string $cert): bool
    {
        return Native::crlCheckCert($crl, $issuerCert, $cert);
    }

    public const CRL_TYPE_DELTA = 0;
    public const CRL_TYPE_FULL = 1;

    /**
     * @param list<int> $f
     */
    public static function verifyDstu4145Pb(
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
        Native::dstu4145VerifyPb($f, $a, $b, $n, $gx, $gy, $qx, $qy, $hash, $r, $s);
    }

    public static function ocspRequestFromCert(string $rootCert, string $userCert): string
    {
        return Native::ocspRequestFromCert($rootCert, $userCert);
    }

    public static function ocspRequestGenerate(
        string $rootCert,
        string $userCert,
        ?PrivateKey $requestorKey = null,
        ?string $ocspResponderCert = null,
        ?string $nonce = null,
        bool $includeNonce = true,
    ): string {
        return Native::ocspRequestGenerate(
            $rootCert,
            $userCert,
            $requestorKey?->nativeHandle(),
            $ocspResponderCert,
            $nonce,
            $includeNonce,
        );
    }

    public static function ocspResponseVerify(string $response, string $ocspResponderCert): void
    {
        Native::ocspResponseVerify($response, $ocspResponderCert);
    }

    public static function ocspResponseValidate(
        string $request,
        string $response,
        string $rootCert,
        int $currentTime,
        int $timeoutMinutes,
    ): void {
        Native::ocspResponseValidate($request, $response, $rootCert, $currentTime, $timeoutMinutes);
    }

    public static function tspRequestFromData(string $data, ?string $policyOid = null, bool $certReq = true): string
    {
        return Native::tspRequestFromData($data, $policyOid, $certReq);
    }

    public static function tspResponseVerify(string $response, string $tsaCert): void
    {
        Native::tspResponseVerify($response, $tsaCert);
    }

    public static function csrVerify(string $csr): void
    {
        Native::csrVerify($csr);
    }

    public static function signCms(string $data, PrivateKey $key): string
    {
        return Native::cmsSign($key->nativeHandle(), $data);
    }

    public static function signCmsCadesT(
        string $data,
        PrivateKey $signKey,
        PrivateKey $tsaKey,
        string $serial,
        int $currentTime,
        ?string $policyOid = null,
    ): string {
        return Native::cmsSignCadesT(
            $signKey->nativeHandle(),
            $tsaKey->nativeHandle(),
            $data,
            $serial,
            $currentTime,
            $policyOid,
        );
    }

    public static function signCmsCadesC(
        string $data,
        PrivateKey $signKey,
        string $refCert,
        string $refCrl,
    ): string {
        if ($refCert === '' || $refCrl === '') {
            throw new InvalidParamError('reference certificate and CRL required');
        }

        return Native::cmsSignCadesC(
            $signKey->nativeHandle(),
            $data,
            $refCert,
            $refCrl,
        );
    }

    public static function signCmsCadesX(
        string $data,
        PrivateKey $signKey,
        string $refCert,
        string $ocspResponse,
    ): string {
        if ($refCert === '' || $ocspResponse === '') {
            throw new InvalidParamError('reference certificate and OCSP response required');
        }

        return Native::cmsSignCadesX(
            $signKey->nativeHandle(),
            $data,
            $refCert,
            $ocspResponse,
        );
    }

    public static function signCmsCadesLt(
        string $data,
        PrivateKey $signKey,
        string $refCert,
        string $fullCrl,
        string $ocspResponse,
        string $deltaCrl = '',
    ): string {
        if ($refCert === '' || $fullCrl === '' || $ocspResponse === '') {
            throw new InvalidParamError('reference certificate, CRL and OCSP response required');
        }

        return Native::cmsSignCadesLt(
            $signKey->nativeHandle(),
            $data,
            $refCert,
            $fullCrl,
            $ocspResponse,
            $deltaCrl,
        );
    }

    public static function signCmsCadesA(
        string $data,
        PrivateKey $signKey,
        PrivateKey $tsaKey,
        string $refCert,
        string $fullCrl,
        string $ocspResponse,
        string $serial,
        int $currentTime,
        string $deltaCrl = '',
        ?string $policyOid = null,
    ): string {
        if ($refCert === '' || $fullCrl === '' || $ocspResponse === '') {
            throw new InvalidParamError('reference certificate, CRL and OCSP response required');
        }

        return Native::cmsSignCadesA(
            $signKey->nativeHandle(),
            $tsaKey->nativeHandle(),
            $data,
            $refCert,
            $fullCrl,
            $ocspResponse,
            $serial,
            $currentTime,
            $deltaCrl,
            $policyOid,
        );
    }

    public static function verifyCms(string $data, string $cms): void
    {
        Native::cmsVerify($data, $cms);
    }

    public static function envelopCms(string $data, PrivateKey $originatorKey, string $recipientCert): string
    {
        if ($recipientCert === '') {
            throw new InvalidParamError('recipient certificate required');
        }

        return Native::cmsEnvelopEncrypt($originatorKey->nativeHandle(), $data, $recipientCert);
    }

    public static function decryptCms(
        string $cms,
        PrivateKey $recipientKey,
        string $recipientCert,
        ?string $originatorCert = null,
        ?string $external = null,
    ): string {
        if ($cms === '' || $recipientCert === '') {
            throw new InvalidParamError('cms and recipient certificate required');
        }

        return Native::cmsEnvelopDecrypt(
            $recipientKey->nativeHandle(),
            $cms,
            $external,
            $originatorCert,
            $recipientCert,
        );
    }
}
