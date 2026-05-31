<?php

declare(strict_types=1);

namespace Itcrow\Uacryptex;

final class PrivateKey
{
    private bool $closed = false;

    public function __construct(
        private \FFI\CData $handle,
        private bool $ownsHandle = true,
    ) {
    }

    public function close(): void
    {
        if ($this->ownsHandle && !$this->closed) {
            Native::handleFree($this->handle);
            $this->closed = true;
        }
    }

    public function signHash(string $digest): string
    {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return Native::signHash($this->handle, $digest);
    }

    public function signData(string $data): string
    {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return Native::signData($this->handle, $data);
    }

    public function ocspResponseGenerate(
        string $request,
        string $rootCert,
        string $userCert,
        string $fullCrl,
        string $deltaCrl,
        int $currentTime,
    ): string {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return Native::ocspResponseGenerate(
            $this->handle,
            $request,
            $rootCert,
            $userCert,
            $fullCrl,
            $deltaCrl,
            $currentTime,
        );
    }

    public function ocspRequestGenerate(
        string $rootCert,
        string $userCert,
        ?string $ocspResponderCert = null,
        ?string $nonce = null,
        bool $includeNonce = true,
    ): string {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return Native::ocspRequestGenerate(
            $rootCert,
            $userCert,
            $this->handle,
            $ocspResponderCert,
            $nonce,
            $includeNonce,
        );
    }

    public function tspResponseGenerate(string $request, string $serial, int $currentTime): string
    {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return Native::tspResponseGenerate($this->handle, $request, $serial, $currentTime);
    }

    public function csrGenerate(
        string $subject,
        ?string $dns = null,
        ?string $email = null,
        ?string $subjectDirAttr = null,
    ): string {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return Native::csrGenerate($this->handle, $subject, $dns, $email, $subjectDirAttr);
    }

    public function generateCertificate(
        string $csr,
        int $version,
        string $serial,
        int $notBefore,
        int $notAfter,
        bool $selfSigned = false,
    ): string {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return Native::certGenerate(
            $this->handle,
            $csr,
            $version,
            $serial,
            $notBefore,
            $notAfter,
            $selfSigned,
        );
    }

    public function generateCrl(
        string $previousCrl,
        int $crlType,
        int $diffNextUpdateSecs,
        ?string $mergeDeltaCrl = null,
        ?string $revokeSerial = null,
        string $templateName = '',
        string $description = '',
    ): string {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return Native::crlGenerate(
            $this->handle,
            $previousCrl,
            $crlType,
            $diffNextUpdateSecs,
            $mergeDeltaCrl,
            $revokeSerial,
            $templateName,
            $description,
        );
    }

    /** @internal */
    public function nativeHandle(): \FFI\CData
    {
        if ($this->closed) {
            throw new InvalidParamError('closed private key');
        }

        return $this->handle;
    }
}
