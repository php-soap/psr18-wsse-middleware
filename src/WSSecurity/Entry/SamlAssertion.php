<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use DOMDocument;
use RobRichards\WsePhp\WSSESoap;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Legacy\LegacyInterop;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\SecurityLocator;

final class SamlAssertion implements WsseEntry
{
    public function __construct(
        private DOMDocument $saml
    ) {
    }

    public function __invoke(DOMDocument $envelope, WSSESoap $wsse): void
    {
        $security = (new SecurityLocator())($envelope);
        $imported = LegacyInterop::disallowFalse(
            $envelope->importNode($this->saml->documentElement, true),
            'Could not import SAML assertion into envelope.'
        );
        $security->appendChild($imported);
    }
}
