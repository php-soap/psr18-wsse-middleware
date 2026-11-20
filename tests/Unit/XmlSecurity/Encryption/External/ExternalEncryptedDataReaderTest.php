<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\XmlSecurity\Encryption\External;

use Dom\Element;
use Phpro\ResourceStream\Factory\MemoryStream;
use Phpro\ResourceStream\ResourceStream;
use PHPUnit\Framework\TestCase;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\KeyStore\SessionKey;
use Soap\Psr18WsseMiddleware\OpenSSL\Cipher;
use Soap\Psr18WsseMiddleware\XmlSecurity\CryptoPolicy;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalEncryptedDataReader;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalPartDecryption;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\DecryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPart;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use VeeWee\Xml\Dom\Document;

/**
 * The reader in isolation, which is the only place its refusals can be told apart. At the block boundary every
 * inbound failure collapses to one SecurityFault by design, so a test there can only prove that something was
 * refused, not which rule did it.
 */
final class ExternalEncryptedDataReaderTest extends TestCase
{
    private const XENC = 'http://www.w3.org/2001/04/xmlenc#';
    private const DS = 'http://www.w3.org/2000/09/xmldsig#';
    private const CONTENT_ONLY = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only';
    private const COMPLETE = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Complete';
    private const CIPHERTEXT_TRANSFORM = 'http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform';
    private const CID = 'cid:invoice@example.com';
    private const PLAINTEXT = '%PDF-1.7 invoice bytes';

    public function test_it_opens_the_part_the_reference_names(): void
    {
        $opened = $this->read($this->element(), $this->parts());

        static::assertSame(self::CID, $opened->reference);
        static::assertSame(self::PLAINTEXT, $opened->content->getContents());
        static::assertSame('application/pdf', $opened->mimeType);
    }

    public function test_it_falls_back_to_the_parts_media_type_when_the_element_declares_none(): void
    {
        $opened = $this->read($this->element(mimeType: null), $this->parts('application/x-original'));

        static::assertSame('application/x-original', $opened->mimeType);
    }

    public function test_it_refuses_a_media_type_that_cannot_be_a_header_value(): void
    {
        // The opened part hands this value back as its Content-Type header, so a line break in it would
        // smuggle a header of the sender's choosing into the attachment.
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('The encrypted part declares a MimeType that cannot be a header value.');

        $this->read($this->element(mimeType: 'text/plain&#13;&#10;X-Injected: yes'), $this->parts());
    }

    public function test_it_refuses_a_reference_naming_a_part_that_was_not_supplied(): void
    {
        // The parts supplied are real and usable; only the reference does not name one of them. Nothing else
        // can refuse this, which is why the wrong-part case needs its own test rather than relying on a
        // digest or tag failure to notice.
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('No supplied part answers the cipher reference.');

        $this->read($this->element(uri: 'cid:stranger@example.com'), $this->parts());
    }

    public function test_it_refuses_a_type_it_does_not_implement(): void
    {
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('The encrypted part declares an unsupported type.');

        $this->read($this->element(type: self::COMPLETE), $this->parts());
    }

    public function test_it_refuses_an_absent_type(): void
    {
        // Element mode is the XML-Enc default for an absent Type, and that default says nothing about which
        // SwA mode produced this. Assuming one would decrypt under a rule the sender never stated.
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('The encrypted part declares an unsupported type.');

        $this->read($this->element(type: null), $this->parts());
    }

    public function test_it_refuses_a_cipher_reference_declaring_another_transform(): void
    {
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('The cipher reference declares an unsupported transform.');

        $this->read($this->element(transform: 'urn:something-else'), $this->parts());
    }

    public function test_it_refuses_a_cipher_reference_declaring_no_transform(): void
    {
        // No transform means the part holds its original bytes, which contradicts the element it sits in.
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('The cipher reference declares no transform.');

        $this->read($this->element(transform: null), $this->parts());
    }

    public function test_it_refuses_a_cipher_reference_declaring_two_transforms(): void
    {
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('The cipher reference must declare one transform.');

        $this->read($this->element(extraTransform: true), $this->parts());
    }

    public function test_it_refuses_a_data_encryption_method_the_policy_rejects(): void
    {
        // The same allow-list the in-document path applies. An external part is not a weaker place to accept
        // a weaker cipher, so a peer naming CBC here is refused exactly as it is there.
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('The data-encryption method is unknown.');

        $this->read($this->element(method: DataEncryptionMethod::AES256_CBC), $this->parts());
    }

    public function test_it_refuses_ciphertext_shorter_than_the_iv_and_tag(): void
    {
        $this->expectException(DecryptionFailed::class);
        $this->expectExceptionMessage('The framed cipher value is too short for the declared method.');

        $this->read($this->element(), ExternalPartList::of(
            new ExternalPart(self::CID, 'application/octet-stream', $this->stream('short')),
        ));
    }

    public function test_supports_is_false_for_an_in_document_cipher_value(): void
    {
        $document = Document::fromXmlString(
            '<xenc:EncryptedData xmlns:xenc="'.self::XENC.'"><xenc:CipherData>'
            .'<xenc:CipherValue>AAA=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>'
        );

        static::assertFalse(
            (new ExternalEncryptedDataReader(new Cipher()))->supports($document->locateDocumentElement()),
        );
    }

    public function test_supports_is_true_for_a_cipher_reference(): void
    {
        static::assertTrue((new ExternalEncryptedDataReader(new Cipher()))->supports($this->element()));
    }

    private function read(Element $element, ExternalPartList $parts): ExternalPart
    {
        return (new ExternalEncryptedDataReader(new Cipher()))->read(
            $element,
            new ExternalPartDecryption($parts, self::CONTENT_ONLY, self::CIPHERTEXT_TRANSFORM),
            $this->sessionKey(),
            CryptoPolicy::default(),
        );
    }

    /**
     * The parts a receiver holds: the ciphertext of PLAINTEXT under the fixed session key, framed exactly as
     * the outbound path writes it.
     */
    private function parts(string $mimeType = 'application/octet-stream'): ExternalPartList
    {
        $cipherText = (new Cipher())->encrypt(
            self::PLAINTEXT,
            $this->sessionKey(),
            DataEncryptionMethod::AES256_GCM,
        );

        return ExternalPartList::of(new ExternalPart(
            self::CID,
            $mimeType,
            $this->stream($cipherText->iv.$cipherText->bytes.($cipherText->tag ?? '')),
        ));
    }

    private function sessionKey(): SessionKey
    {
        return SessionKey::fromBytes(str_repeat("\x2a", 32));
    }

    private function element(
        string $uri = self::CID,
        ?string $type = self::CONTENT_ONLY,
        ?string $transform = self::CIPHERTEXT_TRANSFORM,
        ?string $mimeType = 'application/pdf',
        bool $extraTransform = false,
        DataEncryptionMethod $method = DataEncryptionMethod::AES256_GCM,
    ): Element {
        $transforms = $transform === null
            ? ''
            : '<xenc:Transforms><ds:Transform Algorithm="'.$transform.'"/>'
                .($extraTransform ? '<ds:Transform Algorithm="'.self::CIPHERTEXT_TRANSFORM.'"/>' : '')
                .'</xenc:Transforms>';

        $document = Document::fromXmlString(
            '<xenc:EncryptedData xmlns:xenc="'.self::XENC.'" xmlns:ds="'.self::DS.'"'
            .($type === null ? '' : ' Type="'.$type.'"')
            .($mimeType === null ? '' : ' MimeType="'.$mimeType.'"').'>'
            .'<xenc:EncryptionMethod Algorithm="'.$method->value.'"/>'
            .'<xenc:CipherData><xenc:CipherReference URI="'.$uri.'">'
            .$transforms
            .'</xenc:CipherReference></xenc:CipherData>'
            .'</xenc:EncryptedData>'
        );

        return $document->locateDocumentElement();
    }

    /**
     * @return ResourceStream<resource>
     */
    private function stream(string $contents): ResourceStream
    {
        return MemoryStream::create()->write($contents)->rewind();
    }
}
