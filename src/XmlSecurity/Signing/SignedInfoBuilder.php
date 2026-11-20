<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Signing;

use Closure;
use Dom\Element;
use Dom\Node;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureMethod;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use VeeWee\Xml\Dom\Document;
use function VeeWee\Xml\Dom\Builder\attribute;
use function VeeWee\Xml\Dom\Builder\children;
use function VeeWee\Xml\Dom\Builder\namespaced_element;
use function VeeWee\Xml\Dom\Builder\value;

/**
 * Assembles a ds:SignedInfo element with ds:CanonicalizationMethod, ds:SignatureMethod, and one ds:Reference
 * per SignedReference. The returned element is detached; the caller attaches it as a child of ds:Signature.
 *
 * It emits each reference exactly as given and derives nothing: the URI and the transform chain are the
 * reference's own, because an attachment reference points somewhere that is not a fragment and declares a
 * transform that is not a canonicalization. The canonicalization argument is ds:SignedInfo's own, which is a
 * separate fact from what any reference was digested under.
 */
final class SignedInfoBuilder
{
    /**
     * @param non-empty-list<SignedReference> $references
     * @param list<string>                    $inclusivePrefixes the PrefixList ds:SignedInfo itself is canonicalized under
     */
    public function build(
        Document $document,
        SignatureCanonicalization $canonicalization,
        SignatureMethod $signatureMethod,
        array $references,
        array $inclusivePrefixes = [],
    ): Element {
        $referenceBuilders = array_map(
            fn (SignedReference $reference): callable => $this->reference($reference),
            $references,
        );

        return $document->map(namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('SignedInfo'),
            children(
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('CanonicalizationMethod'),
                    attribute('Algorithm', $canonicalization->value),
                    children(...$this->inclusiveNamespaces($inclusivePrefixes)),
                ),
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('SignatureMethod'),
                    attribute('Algorithm', $signatureMethod->value),
                ),
                ...$referenceBuilders,
            ),
        ));
    }

    /**
     * @return callable(Element): Element
     */
    private function reference(SignedReference $reference): callable
    {
        $transforms = array_map(
            fn (SignedTransform $transform): callable => namespaced_element(
                Namespaces::Ds->value,
                Namespaces::Ds->qualify('Transform'),
                attribute('Algorithm', $transform->algorithm),
                children(...$this->inclusiveNamespaces($transform->inclusivePrefixes)),
            ),
            $reference->transforms,
        );

        return namespaced_element(
            Namespaces::Ds->value,
            Namespaces::Ds->qualify('Reference'),
            attribute('URI', $reference->uri),
            children(
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('Transforms'),
                    children(...$transforms),
                ),
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('DigestMethod'),
                    attribute('Algorithm', $reference->digestMethod->value),
                ),
                namespaced_element(
                    Namespaces::Ds->value,
                    Namespaces::Ds->qualify('DigestValue'),
                    value($reference->digestValueBase64),
                ),
            ),
        );
    }

    /**
     * The ec:InclusiveNamespaces child pinning a PrefixList, or nothing at all. An empty list is
     * indistinguishable from declaring none, so it emits no element. Whether the algorithm is one a
     * PrefixList even parameterizes is decided where the transform is built, since only there is the
     * canonicalization known.
     *
     * @param list<string> $prefixes
     *
     * @return list<Closure(Node): Element>
     */
    private function inclusiveNamespaces(array $prefixes): array
    {
        if ($prefixes === []) {
            return [];
        }

        return [namespaced_element(
            SignatureCanonicalization::EXC_C14N->value,
            'ec:InclusiveNamespaces',
            attribute('PrefixList', implode(' ', $prefixes)),
        )];
    }
}
