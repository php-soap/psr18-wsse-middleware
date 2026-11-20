<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Exception;

use Dom\Node;
use RuntimeException;
use Soap\Psr18WsseMiddleware\Algorithm\SignatureCanonicalization;
use Throwable;

/**
 * Canonicalization could not produce a usable result. The distinct named constructors record the cause for
 * logging and tests; callers never branch on it, they only know the canonicalization was refused.
 *
 * The emptyOutput case refuses an empty canonicalization: digesting an empty result would enable signature
 * replay, so it must never be signed or compared.
 */
final class CanonicalizationFailed extends RuntimeException
{
    public static function emptyOutput(Node $node, SignatureCanonicalization $method): self
    {
        return new self(sprintf(
            'Canonicalizing <%s> with %s produced an empty result; refusing to sign or digest empty canonical output.',
            $node->nodeName,
            $method->name,
        ));
    }

    /**
     * An external part declaring an XML media type whose octets are not a document this package will read.
     *
     * Malformed, or carrying a doctype, which is refused here for the same reason a peer refuses it: a
     * document type definition is a fetch and an expansion instruction attached to bytes somebody else chose.
     * Either way there is no node-set to canonicalize, so there is no digest to compute.
     */
    public static function unreadableExternalPart(?Throwable $previous = null): self
    {
        return new self('An external part declaring an XML media type could not be read as a document.', 0, $previous);
    }

    /**
     * A canonical form that is not an element start tag. No canonicalization of an element produces one, so
     * this is a broken primitive rather than a message a peer can send.
     */
    public static function apexIsNotAnElement(): self
    {
        return new self('A canonical form did not open with an element start tag.');
    }

    public static function excludesEverything(Node $node): self
    {
        return new self(sprintf(
            'Canonicalizing <%s> while excluding it, or an ancestor of it, would leave nothing to digest.',
            $node->nodeName,
        ));
    }

    public static function excludedSubtreeIsElsewhere(Node $node): self
    {
        return new self(sprintf(
            'The subtree to exclude is not inside <%s>, so canonicalizing it would exclude nothing.',
            $node->nodeName,
        ));
    }

    public static function nativeError(Node $node, SignatureCanonicalization $method, ?Throwable $previous = null): self
    {
        return new self(
            sprintf(
                'Canonicalizing <%s> with %s failed inside libxml.',
                $node->nodeName,
                $method->name,
            ),
            0,
            $previous,
        );
    }
}
