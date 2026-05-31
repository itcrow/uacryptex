<?php

declare(strict_types=1);

namespace Itcrow\Uacryptex;

final class Keystore
{
    private bool $closed = false;

    public function __construct(private \FFI\CData $handle)
    {
    }

    public function close(): void
    {
        if (!$this->closed) {
            Native::handleFree($this->handle);
            $this->closed = true;
        }
    }

    public function setCertificate(string $cert): void
    {
        if ($this->closed) {
            throw new InvalidParamError('closed keystore');
        }
        Native::setCertificate($this->handle, $cert);
    }

    public function privateKey(): PrivateKey
    {
        if ($this->closed) {
            throw new InvalidParamError('closed keystore');
        }

        return new PrivateKey($this->handle, ownsHandle: false);
    }

    public function certificateCount(): int
    {
        if ($this->closed) {
            throw new InvalidParamError('closed keystore');
        }

        return Native::pkcs12CertificateCount($this->handle);
    }

    public function getCertificate(int $index): string
    {
        if ($this->closed) {
            throw new InvalidParamError('closed keystore');
        }

        return Native::pkcs12GetCertificate($this->handle, $index);
    }
}
