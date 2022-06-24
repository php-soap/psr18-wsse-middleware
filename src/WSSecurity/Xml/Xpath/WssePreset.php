<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath;

use DOMXPath;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use Soap\Xml\Xmlns;
use VeeWee\Xml\Dom\Document;
use VeeWee\Xml\Dom\Xpath\Configurator\Configurator;
use function VeeWee\Xml\Dom\Locator\root_namespace_uri;
use function VeeWee\Xml\Dom\Xpath\Configurator\namespaces;

final class WssePreset implements Configurator
{
    private Document $document;

    public function __construct(Document $document)
    {
        $this->document = $document;
    }

    public function __invoke(DOMXPath $xpath): DOMXPath
    {
        return namespaces(
            [
                'wssoap' => $this->document->locate(root_namespace_uri()) ?? Xmlns::soap12Envelope()->value(),
                'wswsse' => WSSESoap::WSSENS,
                'wsu' => WSSESoap::WSUNS,
                'ds' => XMLSecurityDSig::XMLDSIGNS,
                'xenc' => XMLSecEnc::XMLENCNS,
            ],
        )($xpath);
    }
}
