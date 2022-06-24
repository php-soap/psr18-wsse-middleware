<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Entry;

use RobRichards\WsePhp\WSSESoap;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator\SecurityLocator;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Locator\document_element;
use function VeeWee\Xml\Dom\Manipulator\Node\append_external_node;

final class SamlAssertion implements WsseEntry
{
    public function __construct(
        private Document $saml
    ) {
    }

    public function __invoke(Document $envelope, WSSESoap $wsse): void
    {
        $security = (new SecurityLocator())($envelope);
        append_external_node($security, $this->saml->locate(document_element()));
    }
}
