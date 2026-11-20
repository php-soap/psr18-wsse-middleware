<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Exception;

use RuntimeException;
use Throwable;

/**
 * Thrown when the octets opened out of an attachment's ciphertext do not carry a readable header block.
 *
 * The caps this reports on are a bound rather than a style rule: the bytes are attacker-supplied by the
 * time they are scanned, so a block that never ends would otherwise be scanned to exhaustion. They match
 * what a legitimate peer applies, so a legitimate peer never trips them.
 */
final class MalformedAttachmentHeaders extends RuntimeException
{
    /**
     * Opened octets holding no CRLF at all, so there is no header line to read and no blank line to stop at.
     * A separate failure from running past the caps, which is what the other two report.
     */
    public static function withoutBlankLine(): self
    {
        return new self('The opened attachment carries no blank line separating its headers from its content.');
    }

    public static function lineTooLong(int $maximumLength): self
    {
        return new self(sprintf(
            'The opened attachment carries a header line longer than %d characters.',
            $maximumLength
        ));
    }

    public static function tooManyHeaders(int $maximumHeaders): self
    {
        return new self(sprintf(
            'The opened attachment carries more than %d headers.',
            $maximumHeaders
        ));
    }

    /**
     * The Content-ID is how a reference bound a digest to this part, so a set arriving from inside the
     * ciphertext that names another one is trying to undo that binding.
     */
    public static function addressesAnotherAttachment(string $found, string $expected): self
    {
        return new self(sprintf(
            'The opened attachment addresses attachment "%s" rather than "%s".',
            $found,
            $expected
        ));
    }

    public static function lineWithoutColon(): self
    {
        return new self('The opened attachment carries a header line that carries no colon.');
    }

    /**
     * A name or value the MIME header collection refuses, such as a folded continuation line that happens
     * to contain a colon, or a value carrying a NUL byte.
     */
    public static function invalidHeader(Throwable $previous): self
    {
        return new self('The opened attachment carries a header that is not a valid MIME header.', 0, $previous);
    }
}
