<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;

use DOMElement;
use RobRichards\WsePhp\WSSESoap;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\BinaryTokenLocator;
use VeeWee\Xml\Dom\Document;

final class BinarySecurityTokenIdentifier implements KeyIdentifier
{
    public function __invoke(Document $envelope, WSSESoap $wsse, DOMElement $parent): void
    {
        $token = (new BinaryTokenLocator())($envelope);
        $tokenUri = $token->getAttributeNS(WSSESoap::WSUNS, 'Id');
        $valueType = $token->getAttribute('ValueType');

        (new ReferencingKeyIdentifier($tokenUri, $valueType))($envelope, $wsse, $parent);
    }
}
