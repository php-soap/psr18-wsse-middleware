<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;

use DOMElement;
use RobRichards\WsePhp\WSSESoap;
use VeeWee\Xml\Dom\Document;

final class SamlKeyIdentifier implements KeyIdentifier
{
    private const VALUE_TYPE = 'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID';
    private KeyIdentifier $keyIdentifier;

    public function __construct(
        string $samlAssertionId
    ) {
        $this->keyIdentifier = new CustomKeyIdentifier($samlAssertionId, self::VALUE_TYPE);
    }
    
    public function __invoke(Document $envelope, WSSESoap $wsse, DOMElement $parent): void
    {
        ($this->keyIdentifier)($envelope, $wsse, $parent);
    }
}
