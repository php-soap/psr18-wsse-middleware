<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMNodeList;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath\WssePreset;
use function Psl\Type\instance_of;

final class SecurityLocator
{
    public function __invoke(DOMDocument $document): DOMElement
    {
        $xpath = WssePreset::xpath($document);
        /** @var DOMNodeList<DOMNode>|false $result */
        $result = $xpath->query('/wssoap:Envelope/wssoap:Header/wswsse:Security');

        return instance_of(DOMElement::class)->assert(
            $result !== false ? $result->item(0) : null
        );
    }
}
