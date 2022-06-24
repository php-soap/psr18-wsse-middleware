<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use RobRichards\WsePhp\WSSESoap;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\KeyInterface;
use VeeWee\Xml\Dom\Document;

final class BinarySecurityToken implements WsseEntry
{
    public function __construct(
        private KeyInterface $publicKey
    ) {
    }

    public function __invoke(Document $envelope, WSSESoap $wsse): void
    {
        $wsse->addBinaryToken($this->publicKey->contents(), isPEMFormat: $this->publicKey->isCertificate());
    }
}
