<?php declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

interface KeyInterface
{
    /**
     * The RAW content of the key.
     */
    public function contents(): string;

    /**
     * The passphrase to open up the key information
     */
    public function passphrase(): string;

    /**
     * Is the key an X509 certificate?
     */
    public function isCertificate(): bool;
}
