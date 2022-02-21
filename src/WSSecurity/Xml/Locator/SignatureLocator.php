<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Xml\Locator;

use DOMElement;
use Psl\Type\Exception\AssertException;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Xpath\WssePreset;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Assert\assert_element;

final class SignatureLocator
{
    /**
     * @throws AssertException
     */
    public function __invoke(Document $document): DOMElement
    {
        return assert_element(
            $document->xpath(new WssePreset($document))
                ->querySingle('/wssoap:Envelope/wssoap:Header/wswsse:Security/ds:Signature')
        );
    }
}
