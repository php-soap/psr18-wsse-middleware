<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyStore;

use ParagonIE\HiddenString\HiddenString;
use function Psl\Filesystem\read_file;

final class Key implements KeyInterface
{
    private HiddenString $key;
    private HiddenString $passphrase;

    public function __construct(string $key)
    {
        $this->key = new HiddenString($key);
        $this->passphrase = new HiddenString('');
    }

    public static function fromFile(string $file): self
    {
        return new self(read_file($file));
    }

    public function withPassphrase(string $passphrase): self
    {
        $new = clone $this;
        $new->passphrase = new HiddenString($passphrase);

        return $new;
    }

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
        return false;
    }
}
