<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External;

use Dom\Element;
use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use SensitiveParameter;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\OpenSSL\CipherText;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Soap\Psr18WsseMiddleware\Xml\ChildElements;
use Soap\Psr18WsseMiddleware\Xml\Namespaces;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptedDataReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Throwable;

/**
 * The mirror of EncryptedDataReader for an xenc:EncryptedData whose ciphertext is not in the document: it
 * validates the declared type, transform and method, resolves the part the CipherReference names from the list
 * the caller supplied, decrypts it, and returns the opened part.
 *
 * It returns rather than restores, which is the difference that matters. There is no node to put plaintext
 * back into: the bytes belong to whatever carried them, and the caller is the only one who knows how to write
 * there.
 */
final class ExternalEncryptedDataReader
{
    public function __construct(
        private readonly Cipher $cipher,
    ) {
    }

    /**
     * True when this element's ciphertext lives outside the document. An element carrying an
     * xenc:CipherValue belongs to the in-document path and is left to EncryptedDataReader.
     */
    public function supports(Element $encryptedDataElement): bool
    {
        $cipherData = ChildElements::single($encryptedDataElement, Namespaces::Xenc, 'CipherData');
        if ($cipherData === null) {
            return false;
        }

        return ChildElements::single($cipherData, Namespaces::Xenc, 'CipherReference') !== null;
    }

    /**
     * @throws DecryptionFailed
     */
    public function read(
        Element $encryptedDataElement,
        ExternalPartDecryption $external,
        SessionKey $sessionKey,
        CryptoPolicy $policy,
    ): ExternalPart {
        try {
            // Structure before crypto. A type other than the one the caller demanded is refused before any
            // decryption rather than attempted and reported as a cipher failure.
            $this->assertType($encryptedDataElement, $external);
            $cipherReference = $this->cipherReference($encryptedDataElement);
            $this->assertTransform($cipherReference, $external);

            $method = $this->method($encryptedDataElement, $policy);
            $part = $this->resolvePart($cipherReference, $external);

            $plaintext = $this->cipher->decrypt(
                $this->frame($part->content->rewind()->getContents(), $method),
                $sessionKey,
                $method,
            );

            return $part->withContent($this->stream($plaintext), $this->mimeType($encryptedDataElement, $part));
        } catch (DecryptionFailed $exception) {
            throw $exception;
        } catch (CryptoOperationFailed | Throwable $exception) {
            throw DecryptionFailed::withReason('Unable to decrypt an encrypted part.', $exception);
        }
    }

    private function assertType(Element $encryptedDataElement, ExternalPartDecryption $external): void
    {
        if ((string) $encryptedDataElement->getAttribute('Type') !== $external->type) {
            throw DecryptionFailed::withReason('The encrypted part declares an unsupported type.');
        }
    }

    private function cipherReference(Element $encryptedDataElement): Element
    {
        $cipherData = $this->child($encryptedDataElement, 'CipherData');

        return $this->child($cipherData, 'CipherReference');
    }

    /**
     * Exactly one transform, and exactly the expected one. A reference declaring none says the part holds the
     * original bytes, which contradicts the element it sits in; declaring several describes a pipeline this
     * package does not run.
     */
    private function assertTransform(Element $cipherReference, ExternalPartDecryption $external): void
    {
        $transforms = ChildElements::single($cipherReference, Namespaces::Xenc, 'Transforms')
            ?? throw DecryptionFailed::withReason('The cipher reference declares no transform.');

        $declared = ChildElements::named($transforms, Namespaces::Ds, 'Transform');
        if (count($declared) !== 1) {
            throw DecryptionFailed::withReason('The cipher reference must declare one transform.');
        }

        if ((string) $declared[0]->getAttribute('Algorithm') !== $external->transform) {
            throw DecryptionFailed::withReason('The cipher reference declares an unsupported transform.');
        }
    }

    /**
     * The same allow-list the in-document path applies, including its refusal of CBC. An external part is not
     * a weaker place to accept a weaker cipher.
     */
    private function method(Element $encryptedDataElement, CryptoPolicy $policy): DataEncryptionMethod
    {
        $encryptionMethod = $this->child($encryptedDataElement, 'EncryptionMethod');
        $algorithm = DataEncryptionMethod::tryFrom((string) $encryptionMethod->getAttribute('Algorithm'));

        if ($algorithm === null || !$policy->acceptsDataEncryptionMethod($algorithm)) {
            throw DecryptionFailed::withReason('The data-encryption method is unknown.');
        }

        return $algorithm;
    }

    /**
     * The part the reference names, from the list the caller supplied. Never fetched: a URI naming anything
     * else is refused, so a message cannot make this package read something the caller did not already hold.
     */
    private function resolvePart(Element $cipherReference, ExternalPartDecryption $external): ExternalPart
    {
        $uri = (string) $cipherReference->getAttribute('URI');

        return $external->parts->byReference($uri)
            ?? throw DecryptionFailed::withReason('No supplied part answers the cipher reference.');
    }

    private function frame(#[SensitiveParameter] string $bytes, DataEncryptionMethod $method): CipherText
    {
        // The raw framing, not base64: the bytes travelled in their own part, so nothing had to escape them.
        $ivLength = $method->ivLength();
        $tagLength = $method->tagLength();

        if (strlen($bytes) < $ivLength + $tagLength) {
            throw DecryptionFailed::withReason('The framed cipher value is too short for the declared method.');
        }

        $iv = substr($bytes, 0, $ivLength);
        if ($tagLength > 0) {
            return new CipherText(
                $iv,
                substr($bytes, $ivLength, strlen($bytes) - $ivLength - $tagLength),
                substr($bytes, -$tagLength),
            );
        }

        return new CipherText($iv, substr($bytes, $ivLength), null);
    }

    /**
     * The media type the sender recorded before encrypting, falling back to what the part currently claims.
     * The attribute is optional in XML-Enc, and the part's own type is the only other thing we know.
     *
     * @return non-empty-string
     */
    private function mimeType(Element $encryptedDataElement, ExternalPart $part): string
    {
        $declared = (string) $encryptedDataElement->getAttribute('MimeType');
        if ($declared === '') {
            return $part->mimeType;
        }

        // The opened part carries this back as its Content-Type header.
        if (strpbrk($declared, "\r\n\0") !== false) {
            throw DecryptionFailed::withReason('The encrypted part declares a MimeType that cannot be a header value.');
        }

        return $declared;
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(#[SensitiveParameter] string $plaintext): ResourceStream
    {
        return MemoryStream::create()->write($plaintext)->rewind();
    }

    private function child(Element $parent, string $localName): Element
    {
        // Exactly one, so an injected sibling cannot shadow the element the decrypt depends on.
        return ChildElements::single($parent, Namespaces::Xenc, $localName)
            ?? throw DecryptionFailed::withReason(sprintf('xenc:%s is missing.', $localName));
    }
}
