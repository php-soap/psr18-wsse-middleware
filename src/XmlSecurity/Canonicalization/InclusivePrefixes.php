<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Canonicalization;

use Dom\Element;
use function VeeWee\Xml\Dom\Locator\Attribute\attributes_list;
use function VeeWee\Xml\Dom\Locator\Attribute\xmlns_attributes_list;
use function VeeWee\Xml\Dom\Locator\Element\ancestors;

/**
 * Derives the exclusive-c14n InclusiveNamespaces PrefixList for an element: the namespace prefixes an
 * exclusive canonicalization would otherwise drop, listed so they survive into the signed bytes.
 *
 * Exclusive C14N emits only the namespace declarations a subtree visibly uses, which is what makes a
 * signature survive being moved into a different envelope. A peer that needs an ancestor's declaration
 * anyway: because it resolves a QName out of attribute or text content, or re-serializes the message:
 * cannot get it back unless the sender pins it here. Nothing is pinned unless the caller asks for it, so
 * the default output stays the narrowest thing the spec allows.
 *
 * The two entry points differ deliberately, matching the shape a WSS4J peer emits: a signed element pins
 * only what it does not already use, while a container pins everything in scope around it, since the
 * SignedInfo canonicalized inside it is a descendant rather than the container itself.
 */
final class InclusivePrefixes
{
    /**
     * The prefixes a signed element inherits but does not itself use. A prefix the element already uses in
     * its own tag or attributes is visibly utilized, so exclusive C14N keeps it without being told to.
     *
     * @return list<string>
     */
    public static function forSignedElement(Element $element): array
    {
        $used = [$element->prefix ?? '#default'];
        foreach (attributes_list($element) as $attribute) {
            // The xmlns prefix is reserved for namespace declarations, which are not prefix usages.
            if ($attribute->prefix !== null && $attribute->prefix !== 'xmlns') {
                $used[] = $attribute->prefix;
            }
        }

        return array_values(array_diff(self::inheritedBy($element), $used));
    }

    /**
     * Every prefix in scope at a container from outside it.
     *
     * @return list<string>
     */
    public static function forContainer(Element $container): array
    {
        return self::inheritedBy($container);
    }

    /**
     * The prefixes declared by the element's ancestors, innermost declaration first and each listed once.
     *
     * @return list<string>
     */
    private static function inheritedBy(Element $element): array
    {
        $prefixes = [];
        foreach (ancestors($element) as $ancestor) {
            foreach (xmlns_attributes_list($ancestor) as $declaration) {
                // A declaration is either xmlns="…" for the default namespace or xmlns:prefix="…"; the
                // PrefixList spells the former '#default'.
                $prefixes[] = 'xmlns' === $declaration->nodeName ? '#default' : $declaration->localName;
            }

            // An ancestor built in memory carries no xmlns attribute yet, but serializing the document emits
            // one for its own prefix binding. Counting that binding here keeps the list the same whether it is
            // derived before or after the round trip through the wire; for an ancestor parsed from the wire the
            // prefix is already declared above and dedupes away.
            if ($ancestor->prefix !== null) {
                $prefixes[] = $ancestor->prefix;
            }
        }

        return array_values(array_unique($prefixes));
    }
}
