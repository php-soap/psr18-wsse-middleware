<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

use ParagonIE\HiddenString\HiddenString;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\PrivateKeyParser;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\X509PublicCertificateParser;
use function Psl\File\read;

/**
 * Contains a PEM bundle of both public X.509 Certificate and an (un)encrypted private key PKCS_8.
 */
final class ClientCertificate implements KeyInterface
{
    private HiddenString $key;
    private HiddenString $passphrase;

    public function __construct(string $key)
    {
        $this->key = new HiddenString($key);
        $this->passphrase = new HiddenString('');
    }

    /**
     * @param non-empty-string $file
     */
    public static function fromFile(string $file): self
    {
        return new self(read($file));
    }

    /**
     * Parse out the private part of the bundled X509 certificate.
     */
    public function privateKey(): Key
    {
        return (new PrivateKeyParser())($this->key, $this->passphrase);
    }

    /**
     * Parse out the public part of the bundled X509 certificate.
     */
    public function publicCertificate(): Certificate
    {
        return (new X509PublicCertificateParser())($this->key);
    }

    /**
     * Provides the full content of the bundled pem certificate.
     */
    public function contents(): string
    {
        return $this->key->getString();
    }

    public function passphrase(): string
    {
        return $this->passphrase->getString();
    }

    public function isCertificate(): bool
    {
        return true;
    }

    public function withPassphrase(string $passphrase): self
    {
        $new = clone $this;
        $new->passphrase = new HiddenString($passphrase);

        return $new;
    }
}
