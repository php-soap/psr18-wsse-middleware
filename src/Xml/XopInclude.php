<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\Xml;

use Dom\Comment;
use Dom\Element;
use Dom\Node;
use Dom\Text;
use VeeWee\Xml\Dom\Document;

/**
 * Whether an element carries its own value or stands in for bytes travelling in a MIME part beside it.
 *
 * MTOM/XOP replaces an element's value with an xop:Include naming the part that holds it. The element is
 * still where the value belongs, so a caller asking "is this element's content really here" has to look for
 * the placeholder rather than at the element's text.
 *
 * The lookup is by namespace, never by local name or prefix: a message binds whatever prefix it likes, and an
 * element a peer happens to have called Include is not a placeholder.
 */
final class XopInclude
{
    /**
     * Public because the emitting side declares the same namespace it matches on: two spellings of one URI is
     * a way for them to disagree.
     */
    public const string NAMESPACE_URI = 'http://www.w3.org/2004/08/xop/include';

    /**
     * Every reference an xop:Include under this element names, in document order.
     *
     * Scoped to the element the caller named. An include belonging to a sibling says nothing about this
     * element's own content.
     *
     * An include carrying no href contributes an empty reference rather than being skipped. It names nothing
     * a caller can supply, so it has to reach the caller as a reference that matches no part; dropping it
     * would let an element hold a placeholder every caller then reads as absent.
     *
     * @return list<string>
     */
    public static function hrefsIn(Document $document, Element $element): array
    {
        return Query::elements(
            $document,
            './/xop:Include | self::xop:Include',
            $element,
            ['xop' => self::NAMESPACE_URI],
        )->reduce(
            /**
             * @param list<string> $hrefs
             *
             * @return list<string>
             */
            static function (array $hrefs, Element $include): array {
                $hrefs[] = (string) $include->getAttribute('href');

                return $hrefs;
            },
            [],
        );
    }

    /**
     * The reference this element stands in for entirely, or null when it does not.
     *
     * Null covers every shape but one: no include at all, a second include beside the first, text or a
     * comment travelling next to it, an include nested below a child, and one naming nothing. All of those
     * are a peer describing an element's content two ways at once, and picking either reading would let the
     * other be injected. Only whitespace is ignored, because pretty-printed XML is the normal case on the
     * wire and a peer ignores text nodes here too.
     *
     * A caller distinguishing "carries its own value" from "is ambiguous" pairs this with hrefsIn(): null
     * here and a non-empty list there is the ambiguity.
     */
    public static function soleHref(Element $element): ?string
    {
        $include = null;

        /** @var Node $child */
        foreach ($element->childNodes as $child) {
            if ($child instanceof Text) {
                if (trim($child->data) !== '') {
                    return null;
                }

                continue;
            }

            if ($child instanceof Comment) {
                return null;
            }

            if ($include !== null || !$child instanceof Element || !self::isInclude($child)) {
                return null;
            }

            $include = $child;
        }

        if ($include === null) {
            return null;
        }

        $href = (string) $include->getAttribute('href');

        return $href === '' ? null : $href;
    }

    private static function isInclude(Element $element): bool
    {
        return $element->namespaceURI === self::NAMESPACE_URI && $element->localName === 'Include';
    }
}
