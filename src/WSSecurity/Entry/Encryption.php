<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Soap\Psr18WsseMiddleware\WSSecurity\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\KeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyInterface;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\EncryptedKeyLocator;
use VeeWee\Xml\Dom\Document;

final class Encryption implements WsseEntry
{
    private KeyInterface $key;
    private KeyIdentifier $keyIdentifier;

    private DataEncryptionMethod $dataEncryptionMethod = DataEncryptionMethod::AES256_CBC;
    private KeyEncryptionMethod $keyEncryptionMethod = KeyEncryptionMethod::RSA_OAEP_MGF1P;

    public function __construct(KeyInterface $key, KeyIdentifier $keyIdentifier)
    {
        $this->key = $key;
        $this->keyIdentifier = $keyIdentifier;
    }

    public function withDataEncryptionMethod(DataEncryptionMethod $dataEncryptionMethod): self
    {
        $new = clone $this;
        $new->dataEncryptionMethod = $dataEncryptionMethod;

        return $new;
    }

    public function withKeyEncryptionMethod(KeyEncryptionMethod $keyEncryptionMethod): self
    {
        $new = clone $this;
        $new->keyEncryptionMethod = $keyEncryptionMethod;

        return $new;
    }

    public function __invoke(Document $envelope, WSSESoap $wsse): void
    {
        $dataEncryptionKey = new XMLSecurityKey($this->dataEncryptionMethod->value);
        $dataEncryptionKey->generateSessionKey();

        $encryptionKey = new XMLSecurityKey($this->keyEncryptionMethod->value, ['type' => 'public']);
        $encryptionKey->passphrase = $this->key->passphrase();
        $encryptionKey->loadKey($this->key->contents(), false, $this->key->isCertificate());

        $wsse->encryptSoapDoc($encryptionKey, $dataEncryptionKey);

        $encryptedKey = (new EncryptedKeyLocator())($envelope);
        ($this->keyIdentifier)($envelope, $wsse, $encryptedKey);
    }
}
