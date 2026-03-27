<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;

use DOMDocument;
use DOMElement;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

final class ReferencingKeyIdentifier implements KeyIdentifier
{
    private string $uriReference;
    private string $valueType;

    public function __construct(string $uriReference, string $valueType)
    {
        $this->uriReference = $uriReference;
        $this->valueType = $valueType;
    }

    public function __invoke(DOMDocument $envelope, WSSESoap $wsse, DOMElement $parent): void
    {
        $keyInfo = $envelope->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:KeyInfo');
        $securityTokenRef = $envelope->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':SecurityTokenReference');
        $reference = $envelope->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':Reference');
        $reference->setAttribute('ValueType', $this->valueType);
        $reference->setAttribute('URI', '#' . $this->uriReference);
        $securityTokenRef->appendChild($reference);
        $keyInfo->appendChild($securityTokenRef);
        $parent->appendChild($keyInfo);
    }
}
