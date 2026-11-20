<?php
declare(strict_types=1);

namespace Soap\Psr18WsseMiddleware\OpenSSL\Parser;

use phpseclib4\File\ASN1;
use phpseclib4\File\ASN1\Types\BaseString;
use phpseclib4\File\ASN1\Types\OID;
use phpseclib4\File\X509;
use Psl\Type\Exception\CoercionException;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\Metadata\DistinguishedName;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CryptoOperationFailed;
use Throwable;
use function Psl\Type\instance_of;
use function Psl\Type\non_empty_vec;
use function Psl\Type\shape;
use function Psl\Type\vec;

/**
 * Reads a certificate's subject and issuer as the sequence of relative names they actually are.
 *
 * openssl's own parse reports a name as a map of attribute type to value, which collapses repeated types
 * (the LDAP / AD CS layout with several OU components) into one entry and loses both the boundaries between
 * relative names and their order. That is not enough to render RFC 2253, which XML-DSig requires for
 * ds:X509IssuerName: a comma separates two relative names while a plus sign joins the values of a single
 * multi-valued one, so the two forms describe different names and cannot be guessed apart afterwards. This
 * reads the encoded sequence instead, where each relative name and its values are still distinct, and it
 * covers the issuer as well: openssl exposes a lossless form for the subject alone.
 */
final class DistinguishedNameParser
{
    /**
     * The attribute types RFC 2253 gives a short name to. Anything else keeps its dotted-decimal object
     * identifier, which the same section prescribes.
     */
    private const SHORT_NAMES = [
        '2.5.4.3' => 'CN',
        '2.5.4.6' => 'C',
        '2.5.4.7' => 'L',
        '2.5.4.8' => 'ST',
        '2.5.4.9' => 'STREET',
        '2.5.4.10' => 'O',
        '2.5.4.11' => 'OU',
        '0.9.2342.19200300.100.1.1' => 'UID',
        '0.9.2342.19200300.100.1.25' => 'DC',
    ];

    /**
     * @return array{subject: DistinguishedName, issuer: DistinguishedName}
     *
     * @throws CryptoOperationFailed when the certificate cannot be read, or carries a name this cannot
     *         render as text, and is refused rather than approximated, since a distinguished name is matched
     *         against a trust anchor and a name that reads differently is a different identity
     */
    public function parse(Certificate $certificate): array
    {
        try {
            $x509 = X509::load($certificate->contents());

            return [
                'subject' => $this->fromEncodedName($x509->getSubjectDN(X509::DN_ARRAY)),
                'issuer' => $this->fromEncodedName($x509->getIssuerDN(X509::DN_ARRAY)),
            ];
        } catch (Throwable) {
            throw CryptoOperationFailed::unreadableCertificate();
        }
    }

    /**
     * Renders an encoded name (phpseclib's DN_ARRAY form, an rdnSequence) as a DistinguishedName.
     *
     * Public because a certificate is not the only thing that carries a name to compare: a CRL states the issuer
     * it speaks for, and that name has to be rendered by this exact code to be comparable. Phpseclib's own
     * DN_STRING joins the sequence in encoded order, least-specific first, while RFC 2253 (and so
     * DistinguishedName) is most-specific first: so rendering the two sides by different routes makes every
     * multi-attribute name compare unequal.
     *
     * @throws CryptoOperationFailed
     */
    public function fromEncodedName(mixed $name): DistinguishedName
    {
        try {
            $sequence = shape([
                'rdnSequence' => vec(non_empty_vec(shape([
                    'type' => instance_of(OID::class),
                    'value' => instance_of(BaseString::class),
                ], true))),
            ], true)->coerce($name);
        } catch (CoercionException) {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        $relativeNames = [];
        foreach ($sequence['rdnSequence'] as $relativeName) {
            $pairs = [];
            foreach ($relativeName as $pair) {
                $pairs[] = [
                    'type' => $this->type($pair['type']),
                    // The string as encoded: a BMPString or TeletexString value is not transcoded here.
                    'value' => $pair['value']->value,
                ];
            }

            $relativeNames[] = $pairs;
        }

        return DistinguishedName::fromRelativeNames($relativeNames);
    }

    /**
     * @return non-empty-string
     *
     * @throws CryptoOperationFailed when the attribute type is empty
     */
    private function type(OID $type): string
    {
        // The OID renders as its label when phpseclib knows one and as the dotted identifier otherwise; both
        // normalize to the identifier, which is what the short-name table is keyed by.
        $oid = ASN1::getOIDFromName((string) $type);
        if ($oid === '') {
            throw CryptoOperationFailed::unreadableCertificate();
        }

        return self::SHORT_NAMES[$oid] ?? $oid;
    }
}
