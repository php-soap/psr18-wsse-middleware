<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\WSSecurity\Outbound;

use InvalidArgumentException;
use LogicException;
use Soap\Psr18WsseMiddleware\Algorithm\DataEncryptionMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentEncryptedDataType;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\CipherValueParts;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentCoverage;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\KeyRequest;
use Soap\Psr18WsseMiddleware\WSSecurity\Keys\SymmetricKeySource;
use Soap\Psr18WsseMiddleware\WSSecurity\Part;
use Soap\Psr18WsseMiddleware\WSSecurity\WsseContext;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\Builder\SecurityHeader;
use Soap\Psr18WsseMiddleware\WSSecurity\Xml\WsuIdConvention;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionRequest;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\EncryptionTarget;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\Encryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\External\ExternalPartEncryption;
use Soap\Psr18WsseMiddleware\XmlSecurity\Encryption\XmlEncryptor;
use Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartList;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalParts;

/**
 * Encrypts the requested parts of the outbound message via XML-Enc. Configuration:
 *   - where the session key comes from, via a SymmetricKeySource: a GeneratedSessionKey mints one and carries it
 *     to the recipient in an xenc:EncryptedKey, which is what this block used to do on its own
 *   - which parts to encrypt (default: Body only; override via withParts)
 *   - algorithms (default: the profile carried on the context; override per block)
 *
 * The key source is asked for exactly as many bytes as the data-encryption method takes, and a source already
 * carrying a key of a different width is refused rather than serving one the cipher cannot use.
 *
 * The xenc:ReferenceList naming the encrypted parts goes inside the xenc:EncryptedKey when this block is alone
 * with its key, which is the shape every stack has always read. A key shared with another block goes the other
 * way: the list stands beside the key in the Security header and each xenc:EncryptedData carries a ds:KeyInfo
 * naming the key, because whoever took the key first may already have signed the element carrying it and this
 * block must not write into it.
 *
 * The Security header is guaranteed to exist before the encryptor runs. Algorithm resolution order:
 * per-block override, then the profile carried on the context.
 *
 * Intended position in the outbound list: after Outbound\Signature (sign-then-encrypt). The engine
 * places xenc:EncryptedKey before ds:Signature in the Security header; this block takes no action on it.
 */
final class Encryption implements OutboundAction
{
    private const OPAQUE_MEDIA_TYPE = 'application/octet-stream';

    /** @var list<Part>|null */
    private ?array $parts = null;

    private ?DataEncryptionMethod $dataEncryptionMethod = null;
    private ?ExternalParts $attachments = null;
    private ?ExternalParts $cipherCarriers = null;

    private ?XmlEncryptor $encryptor = null;

    public function __construct(
        private readonly SymmetricKeySource $key,
    ) {
    }

    /**
     * A caller replacing the encryptor owns everything the default one does, withOptimizedCipherBytes()
     * included: the replacement is used exactly as given.
     */
    public function withEncryptor(XmlEncryptor $encryptor): self
    {
        $clone = clone $this;
        $clone->encryptor = $encryptor;

        return $clone;
    }

    /**
     * Writes the cipher bytes into MIME parts and leaves an xop:Include in each xenc:CipherValue, instead of
     * base64 in the document.
     *
     * Off by default and nothing negotiates it. It buys the 33% that base64 costs, which is worth having on
     * large payloads and worth nothing on small ones, and no policy assertion can require it of either side.
     * A WSS4J or CXF peer reads this shape whatever its own configuration says, because resolving a cipher
     * value's pointer is not something those peers made optional.
     *
     * Pass AttachmentParts::request() for the outbound side. The request becomes a multipart one, so the
     * attachments middleware has to be in the pipeline, and under MTOM that means a SOAP 1.2 envelope.
     *
     * Not to be combined with encrypt-then-sign: the minted parts are not registered on the signing block, so
     * signing an element that now holds a pointer is refused. WSS4J silently disables this option in that
     * case instead; a security-relevant setting that turns itself off is not a behaviour to copy.
     */
    public function withOptimizedCipherBytes(ExternalParts $carriers): self
    {
        $clone = clone $this;
        $clone->cipherCarriers = $carriers;

        return $clone;
    }

    /**
     * Built per message rather than in the constructor, so an explicit encryptor and an optimized-bytes
     * registration cannot depend on which was configured first.
     *
     * The WS-Security profile mandates wsu:Id on the xenc:EncryptedData, so the block injects the wsu:Id
     * convention. The engine's own default (xml:id) would break the WSSE wire format.
     */
    private function encryptor(): XmlEncryptor
    {
        return $this->encryptor ?? Encryptor::create(
            new WsuIdConvention(),
            $this->cipherCarriers === null ? null : new CipherValueParts($this->cipherCarriers),
        );
    }

    /**
     * An empty list is refused rather than read as "the default": encrypting nothing still wraps a session key
     * and appends an xenc:EncryptedKey, so the Body would leave in cleartext under a message that reads as
     * encrypted everywhere it is logged or captured.
     *
     * Declared as a plain list rather than a non-empty one on purpose: a static constraint is not a guard, and
     * the list a caller passes is routinely built from configuration a type checker never sees.
     *
     * @param list<Part> $parts
     */
    public function withParts(array $parts): self
    {
        $clone = clone $this;
        $clone->parts = $parts;

        return $clone;
    }

    /**
     * Encrypts the message's attachments alongside its in-document parts, under the same session key.
     *
     * Under the same key and in the same operation, not as a second block: the profile wants one
     * xenc:EncryptedKey whose single ReferenceList names the in-document parts and the attachment parts
     * together, and a receiver refuses a second key in the header.
     *
     * The sealed parts are written back with an opaque media type, since their bytes are no longer of the type
     * they claimed. The original type is recorded on the xenc:EncryptedData so the far side can restore it.
     *
     * Pass AttachmentParts::request() for the outbound side. To also sign them, put Outbound\Signature first
     * with the same registration: it digests the plaintext, and this block then replaces it with ciphertext.
     */
    public function withAttachments(ExternalParts $attachments): self
    {
        $clone = clone $this;
        $clone->attachments = $attachments;

        return $clone;
    }

    public function withDataEncryptionMethod(DataEncryptionMethod $method): self
    {
        $clone = clone $this;
        $clone->dataEncryptionMethod = $method;

        return $clone;
    }

    /**
     * @throws \Soap\Psr18WsseMiddleware\WSSecurity\Exception\WsseHeaderException when the header cannot be created
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\IdStampFailed when an encrypted part cannot carry a wsu:Id
     * @throws \Soap\Psr18WsseMiddleware\XmlSecurity\Exception\EncryptionFailed when encryption fails
     */
    public function __invoke(WsseContext $context): void
    {
        $document = $context->document();

        $security = SecurityHeader::forContext($context);
        $profile = $context->profile();

        $dataEncryptionMethod = $this->dataEncryptionMethod ?? $profile->crypto()->dataEncryptionMethod();
        // Mandatory: a cipher takes the width its algorithm defines, and a key of any other size is one it
        // cannot use rather than a weaker choice.
        $key = $this->key->resolve($context, KeyRequest::exactly($dataEncryptionMethod->keyLength()));

        // A block alone with its key nests the reference list inside the element carrying that key, which is the
        // shape every stack has always read and which needs nothing said on each xenc:EncryptedData. Sharing the
        // key rules that out: whoever took it first may already have signed the element, so the list stands
        // beside it and each xenc:EncryptedData names the key instead.
        $nestIn = $context->keys()->isShared($this->key) ? null : $key->referenceListCarrier;

        $parts = $this->parts ?? [Part::body()];
        $soapVersion = $context->soapVersion();
        $external = $this->externalPartEncryption();

        if ($parts === [] && $external === null) {
            // Encrypting nothing still wraps a session key and appends an xenc:EncryptedKey, so the message
            // would leave with a plaintext Body while reading as encrypted in every log and capture of it.
            throw new InvalidArgumentException('Encryption needs at least one part to encrypt.');
        }
        $request = new EncryptionRequest(
            container: $security->element(),
            targets: array_map(
                static fn (Part $part): EncryptionTarget => new EncryptionTarget(
                    $part->toTarget($soapVersion),
                    // A null mode marks a signing-only part (securityHeaderContents/soapHeaders): not encryptable.
                    $part->encryptionMode() ?? throw new LogicException(
                        'A signing-only Part (securityHeaderContents/soapHeaders) cannot be encrypted.',
                    ),
                ),
                $parts,
            ),
            sessionKey: $key->bytes,
            dataEncryptionMethod: $dataEncryptionMethod,
            keyIdentifier: $nestIn === null ? $key->keyIdentifier : null,
            externalParts: $external,
            nestReferenceListIn: $nestIn,
        );

        $result = $this->encryptor()->encrypt($document, $request);
        $this->assertEveryRegisteredPartSealed($external?->parts, $result->sealedParts);

        if ($this->attachments !== null) {
            $this->attachments->replace($this->opaque($result->sealedParts));
        }

        // The engine appends the encrypted key; which order this header must be in is the profile's rule.
        $security->sort();
    }

    /**
     * Every part handed to the encryptor must come back sealed.
     *
     * The encryptor reports what it sealed instead of the block trusting the request it sent, because the
     * encryptor is a seam a caller may replace. One that returns less than it was handed would leave the
     * attachment in the storage as plaintext under a message that carries an xenc:EncryptedKey and reads as
     * encrypted in every log and packet capture of it.
     *
     * @throws EncryptionFailed
     */
    private function assertEveryRegisteredPartSealed(
        ?ExternalPartList $registeredAttachments,
        ExternalPartList $sealed,
    ): void {
        foreach ($registeredAttachments ?? ExternalPartList::of() as $part) {
            if ($sealed->byReference($part->reference) === null) {
                throw EncryptionFailed::withReason(sprintf(
                    'The encryption does not cover the external part "%s", which was registered.',
                    $part->reference,
                ));
            }
        }
    }

    /**
     * The SwA type and transform are this block's to declare, exactly as it owns lowering a Part into an
     * EncryptionTarget. The engine is handed two URIs and a list of parts and never learns they are
     * attachments.
     *
     * Collected here rather than at wiring time because the storage holds the message in flight.
     */
    private function externalPartEncryption(): ?ExternalPartEncryption
    {
        $attachments = $this->attachments;
        if ($attachments === null) {
            return null;
        }

        if ($attachments->coverage() !== ExternalPartCoverage::Content) {
            throw UnsupportedAttachmentCoverage::outboundEncryption();
        }

        return new ExternalPartEncryption(
            $attachments->collectSealed(),
            AttachmentEncryptedDataType::ContentOnly->value,
            AttachmentEncryptedDataType::CIPHERTEXT_TRANSFORM,
        );
    }

    /**
     * Ciphertext is not of the media type the plaintext was, and saying otherwise invites a reader to parse
     * it. The type the far side needs in order to restore the part travels on the xenc:EncryptedData instead.
     */
    private function opaque(ExternalPartList $sealed): ExternalPartList
    {
        $opaque = [];
        foreach ($sealed as $part) {
            $opaque[] = $part->withContent($part->content, self::OPAQUE_MEDIA_TYPE);
        }

        return ExternalPartList::of(...$opaque);
    }
}
