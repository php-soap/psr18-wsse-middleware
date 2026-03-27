<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath;

use DOMDocument;
use DOMXPath;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use Soap\Xml\Xmlns;

final class WssePreset
{
    public static function xpath(DOMDocument $document): DOMXPath
    {
        $xpath = new DOMXPath($document);
        $rootNs = $document->documentElement?->namespaceURI ?? Xmlns::soap12Envelope()->value();
        $xpath->registerNamespace('wssoap', $rootNs);
        $xpath->registerNamespace('wswsse', WSSESoap::WSSENS);
        $xpath->registerNamespace('wsu', WSSESoap::WSUNS);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
        $xpath->registerNamespace('xenc', XMLSecEnc::XMLENCNS);

        return $xpath;
    }
}
