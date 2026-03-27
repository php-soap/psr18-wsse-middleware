<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;

use DOMDocument;
use DOMElement;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

final class CustomKeyIdentifier implements KeyIdentifier
{
    private string $identifier;
    private string $valueType;
    /**
     * @var array<string, string>
     */
    private array $attributes = [];

    public function __construct(string $identifier, string $valueType)
    {
        $this->identifier = $identifier;
        $this->valueType = $valueType;
    }

    /**
     * @param array<string, string> $attributes
     */
    public function withAttributes(array $attributes): self
    {
        $new = clone $this;
        $new->attributes = $attributes;

        return $new;
    }

    public function __invoke(DOMDocument $envelope, WSSESoap $wsse, DOMElement $parent): void
    {
        $keyInfo = $envelope->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:KeyInfo');
        $securityTokenRef = $envelope->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':SecurityTokenReference');
        $keyIdentifier = $envelope->createElementNS(WSSESoap::WSSENS, WSSESoap::WSSEPFX . ':KeyIdentifier');
        $keyIdentifier->setAttribute('ValueType', $this->valueType);
        foreach ($this->attributes as $name => $val) {
            $keyIdentifier->setAttribute($name, $val);
        }
        $keyIdentifier->nodeValue = $this->identifier;
        $securityTokenRef->appendChild($keyIdentifier);
        $keyInfo->appendChild($securityTokenRef);
        $parent->appendChild($keyInfo);
    }
}
