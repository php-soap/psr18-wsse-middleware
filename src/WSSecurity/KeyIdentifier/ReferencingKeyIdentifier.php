<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;

use DOMElement;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;

final class ReferencingKeyIdentifier implements KeyIdentifier
{
    private string $uriReference;
    private string $valueType;

    public function __construct(string $uriReference, string $valueType)
    {
        $this->uriReference = $uriReference;
        $this->valueType = $valueType;
    }

    /**
     * @psalm-suppress ArgumentTypeCoercion - psalm is not able to determine DOMNode - DOMElement confusion for now.
     */
    public function __invoke(Document $envelope, WSSESoap $wsse, DOMElement $parent): void
    {
        $keyInfo = $envelope->build(
            namespaced_element(
                XMLSecurityDSig::XMLDSIGNS,
                'ds:KeyInfo',
                children(
                    namespaced_element(
                        WSSESoap::WSSENS,
                        WSSESoap::WSSEPFX . ':SecurityTokenReference',
                        children(
                            namespaced_element(
                                WSSESoap::WSSENS,
                                WSSESoap::WSSEPFX . ':Reference',
                                attribute('ValueType', $this->valueType),
                                attribute('URI', '#' . $this->uriReference)
                            )
                        )
                    )
                )
            )
        );

        $parent->append(...$keyInfo);
    }
}
