<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use RobRichards\WsePhp\WSSESoap;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyInterface;
use VeeWee\Xml\Dom\Document;

final class Decryption implements WsseEntry
{
    private KeyInterface $key;

    public function __construct(KeyInterface $key)
    {
        $this->key = $key;
    }

    public function __invoke(Document $envelope, WSSESoap $wsse): void
    {
        $wsse->decryptSoapDoc(
            $envelope->toUnsafeDocument(),
            [
                'keys' => [
                    'private' => [
                        'key'    => $this->key->contents(),
                        'isFile' => false,
                        'isCert' => $this->key->isCertificate(),
                        'passphrase' => $this->key->passphrase(),
                    ]
                ]
            ]
        );
    }
}
