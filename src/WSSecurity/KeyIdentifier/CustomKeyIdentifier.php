<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier;

use DOMElement;
use RobRichards\WsePhp\WSSESoap;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\attributes;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

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
                                WSSESoap::WSSEPFX . ':KeyIdentifier',
                                attribute('ValueType', $this->valueType),
                                attributes($this->attributes),
                                value($this->identifier)
                            )
                        )
                    )
                )
            )
        );

        $parent->append(...$keyInfo);
    }
}
