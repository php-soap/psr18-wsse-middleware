<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Attachment;

use Psl\MIME\Exception\InvalidArgumentException;
use Psl\MIME\Headers;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\MalformedAttachmentHeaders;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentHeaderForm;

/**
 * The header block that precedes an attachment's bytes when a protection covers its transport metadata as
 * well as its content.
 *
 * The canonical form and the wire form are two views of one thing, which is why they share a class: they
 * share the five-header selection rule and never vary independently. It takes a header collection rather
 * than an attachment, so AttachmentParts stays the only class here that names the attachments package.
 */
final readonly class MimeHeaderBlock
{
    /**
     * The caps a peer applies while reading a header block out of opened octets. They bound a scan over
     * attacker-supplied bytes, and matching the peer is what keeps a legitimate message under them.
     */
    public const int MAX_HEADERS = 100;

    public const int MAX_LINE_LENGTH = 1000;

    /**
     * The only headers a coverage of a part's metadata considers, ascending, which is also the order they
     * are emitted in.
     *
     * @var list<string>
     */
    private const array PROFILE_HEADERS = [
        'Content-Description',
        'Content-Disposition',
        'Content-ID',
        'Content-Location',
        'Content-Type',
    ];

    /**
     * The parameters whose values carry no case, and are therefore lowercased before being quoted.
     *
     * @var list<string>
     */
    private const array CASELESS_PARAMETERS = [
        'charset',
        'creation-date',
        'filename',
        'modification-date',
        'padding',
        'read-date',
        'size',
        'type',
    ];

    /**
     * What a peer substitutes for a part that travelled without a Content-Type, which is why an absent one
     * is never filled in earlier: the absence is the thing both sides have to agree on.
     */
    private const string ABSENT_CONTENT_TYPE = 'text/plain;charset="us-ascii"';

    /**
     * The digest form: the profile's headers, normalized, ascending by name, one CRLF each.
     *
     * No blank line closes the block. The bytes of the part follow the last CRLF directly.
     *
     * @throws UnsupportedAttachmentHeaderForm
     */
    public function canonicalize(Headers $headers): string
    {
        $canonical = [];
        foreach (self::PROFILE_HEADERS as $name) {
            $values = $headers->all($name);
            if ($values === []) {
                continue;
            }

            if (count($values) > 1) {
                throw UnsupportedAttachmentHeaderForm::duplicate($name, count($values));
            }

            $canonical[$name] = $this->canonicalValue($name, $values[0]);
        }

        // Last in ascending order too, so a substituted one needs no re-sorting.
        $canonical['Content-Type'] ??= self::ABSENT_CONTENT_TYPE;

        $block = '';
        foreach ($canonical as $name => $value) {
            $block .= $name.':'.$value."\r\n";
        }

        return $block;
    }

    /**
     * Splits octets at the first blank line into the headers they carry and the bytes after them.
     *
     * Read here rather than through a general MIME reader, because two of the rules are the point: a line
     * carrying no colon is refused rather than skipped, and so is a folded one, since a peer restores what
     * it split rather than what it could make sense of. The caps bound the scan.
     *
     * @throws MalformedAttachmentHeaders
     */
    public function decode(string $octets): DecodedPart
    {
        $pairs = [];
        $offset = 0;

        while (true) {
            $end = strpos($octets, "\r\n", $offset);
            if ($end === false) {
                throw MalformedAttachmentHeaders::withoutBlankLine();
            }

            if ($end - $offset > self::MAX_LINE_LENGTH) {
                throw MalformedAttachmentHeaders::lineTooLong(self::MAX_LINE_LENGTH);
            }

            $line = substr($octets, $offset, $end - $offset);
            $offset = $end + 2;

            if ($line === '') {
                try {
                    $headers = Headers::fromPairs($pairs);
                } catch (InvalidArgumentException $error) {
                    throw MalformedAttachmentHeaders::invalidHeader($error);
                }

                return new DecodedPart($headers, substr($octets, $offset));
            }

            if (count($pairs) === self::MAX_HEADERS) {
                throw MalformedAttachmentHeaders::tooManyHeaders(self::MAX_HEADERS);
            }

            $colon = strpos($line, ':');
            if ($colon === false) {
                throw MalformedAttachmentHeaders::lineWithoutColon();
            }

            $pairs[] = [substr($line, 0, $colon), ltrim(substr($line, $colon + 1), " \t")];
        }
    }

    /**
     * @throws UnsupportedAttachmentHeaderForm
     */
    private function canonicalValue(string $name, string $value): string
    {
        if ($name === 'Content-Description') {
            throw UnsupportedAttachmentHeaderForm::contentDescription();
        }

        $value = ltrim($value, " \t");
        $this->refuseComment($name, $value);

        if ($name === 'Content-Disposition' || $name === 'Content-Type') {
            return $this->canonicalParameters($name, $value);
        }

        return $value;
    }

    /**
     * @throws UnsupportedAttachmentHeaderForm
     */
    private function refuseComment(string $name, string $value): void
    {
        $quoted = false;
        foreach (str_split($value) as $character) {
            if ($character === '"') {
                $quoted = !$quoted;

                continue;
            }

            if ($character === '(' && !$quoted) {
                throw UnsupportedAttachmentHeaderForm::comment($name);
            }
        }
    }

    /**
     * A value with parameters is rewritten: the part before the first semicolon lowercased, the parameter
     * names lowercased and sorted, and every value quoted. A value without parameters is left as it stands,
     * which is why a media type only loses its case when it carries one.
     *
     * The splitting is deliberately naive, and a correct parser here would be a bug. A peer splits this on
     * every semicolon, including one inside a quoted filename, and the digest both sides have to arrive at
     * is the one taken over what the peer produced. Parsing it properly yields a form no peer computes.
     *
     * @throws UnsupportedAttachmentHeaderForm
     */
    private function canonicalParameters(string $name, string $value): string
    {
        if (!str_contains($value, ';')) {
            return $value;
        }

        $parts = explode(';', $value);
        while (count($parts) > 1 && end($parts) === '') {
            array_pop($parts);
        }

        $parameters = [];
        foreach (array_slice($parts, 1) as $part) {
            $separator = strpos($part, '=');
            if ($separator === false) {
                throw UnsupportedAttachmentHeaderForm::unreadableParameter($name);
            }

            $parameterName = strtolower(trim(substr($part, 0, $separator)));
            if (str_contains($parameterName, '*')) {
                throw UnsupportedAttachmentHeaderForm::continuedParameter($name);
            }

            $parameterValue = trim(substr($part, $separator + 1));
            if ($parameterValue === '') {
                throw UnsupportedAttachmentHeaderForm::unreadableParameter($name);
            }

            if (in_array($parameterName, self::CASELESS_PARAMETERS, true)) {
                $parameterValue = strtolower($parameterValue);
            }

            $parameters[$parameterName] = $this->unquoteInner($this->quote($parameterValue));
        }

        ksort($parameters, SORT_STRING);

        $canonical = strtolower($parts[0]);
        foreach ($parameters as $parameterName => $parameterValue) {
            $canonical .= ';'.$parameterName.'='.$parameterValue;
        }

        return $canonical;
    }

    private function quote(string $value): string
    {
        $starts = $value[0] === '"';
        $ends = $value[strlen($value) - 1] === '"';

        return match (true) {
            $starts && $ends => $value,
            $starts => $value.'"',
            $ends => '"'.$value,
            default => '"'.$value.'"',
        };
    }

    /**
     * Escapes a quote that the value carries and unescapes anything else that was escaped, so a value that
     * came in quoted and one that came in bare end up written the same way.
     */
    private function unquoteInner(string $value): string
    {
        $unquoted = '';
        $length = strlen($value);

        for ($i = 0; $i < $length - 1; $i++) {
            $character = $value[$i];
            $next = $value[$i + 1];

            if ($i === 0 && $character === '"') {
                $unquoted .= $character;

                continue;
            }

            if ($character === '\\' && ($next === '"' || $next === '\\')) {
                if ($i !== 0 && $i !== $length - 2) {
                    $unquoted .= $character;
                }

                $unquoted .= $next;
                $i++;

                continue;
            }

            if ($character === '"') {
                $unquoted .= '\\"';

                continue;
            }

            if ($character === '\\') {
                $unquoted .= $next;
                $i++;

                continue;
            }

            $unquoted .= $character;
            if ($i === $length - 2 && $next === '"') {
                $unquoted .= $next;
            }
        }

        return $unquoted;
    }
}
