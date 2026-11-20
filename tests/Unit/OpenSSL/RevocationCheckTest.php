<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\OpenSSL;

use phpseclib4\Crypt\RSA;
use phpseclib4\File\CRL;
use phpseclib4\File\X509;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psl\DateTime\Timestamp;
use Soap\Psr18WsseMiddleware\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateChain;
use Soap\Psr18WsseMiddleware\KeyStore\CertificateRevocationList;
use Soap\Psr18WsseMiddleware\KeyStore\Exception\InvalidTrustStore;
use Soap\Psr18WsseMiddleware\KeyStore\TrustStore;
use Soap\Psr18WsseMiddleware\OpenSSL\CertificateTrust;
use Soap\Psr18WsseMiddleware\OpenSSL\Exception\CertificateTrustException;
use Soap\Psr18WsseMiddleware\OpenSSL\Parser\DistinguishedNameParser;
use SoapTest\Psr18WsseMiddleware\Unit\Clock\FrozenClock;

/**
 * Revocation is opt-in, and once opted in it is fail-closed: a signer is accepted only when a list that is
 * trusted, current, and issued by the signer's own issuer says nothing about it. Every other outcome: revoked,
 * no list covering that issuer, a list past its nextUpdate, or a list whose signature does not verify against an
 * anchor: rejects. Revocation that silently skips the issuers you forgot to supply is worse than none, because
 * the configuration reads as enabled.
 *
 * Every rejection here asserts the reason, not just the exception type. Every trust failure shares one exception
 * class, so a test that only asserted the class would pass whichever rule fired: and each of these scenarios can
 * fail for more than one reason at once. Asserting the message is what pins the rule under test; the uniform,
 * non-identifying fault a peer sees is produced further out, at the SecurityFault boundary.
 */
final class RevocationCheckTest extends TestCase
{
    /**
     * 2036-01-01. Past the short-lived list's nextUpdate (a day after generation) but far inside the leaf's
     * validity (2056), so staleness fires without the certificate-expiry check firing first.
     */
    private const AFTER_SHORT_LIST_EXPIRED = 2082758400;

    public function test_without_revocation_lists_a_revoked_leaf_still_verifies(): void
    {
        // The opt-in half: revocation is off by default, matching WSS4J's ENABLE_REVOCATION=false.
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt')),
        );

        static::assertStringContainsString('WSSE Revocation Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_leaf_absent_from_a_current_list_is_accepted(): void
    {
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            $this->trustWith('crl-empty.pem'),
        );

        static::assertStringContainsString('WSSE Revocation Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_revoked_leaf_is_rejected(): void
    {
        $this->assertRejectedBecause(
            'listed as revoked',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                $this->trustWith('crl-revoked.pem'),
            ),
        );
    }

    public function test_a_list_from_another_issuer_does_not_cover_our_signer(): void
    {
        // Fail closed on missing: a list is supplied, but not one issued by the signer's issuer, so nothing
        // vouches for this certificate. The unrelated CA is also anchored here, so the list is genuinely
        // trusted: otherwise this would pass on the signature rule instead of the coverage rule.
        $this->assertRejectedBecause(
            'No supplied revocation list covers the issuer',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                TrustStore::fromCertificates($this->certificate('ca.crt'), $this->certificate('other-ca.crt'))
                    ->withRevocationLists($this->revocationList('crl-other-ca.pem')),
            ),
        );
    }

    public function test_a_list_past_its_next_update_is_rejected(): void
    {
        $this->assertRejectedBecause(
            'past its nextUpdate',
            fn (): mixed => (new CertificateTrust())
                ->withClock(new FrozenClock(Timestamp::fromParts(self::AFTER_SHORT_LIST_EXPIRED)))
                ->verify(
                    CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                    $this->trustWith('crl-short.pem'),
                ),
        );
    }

    public function test_the_staleness_rule_does_not_reject_a_still_current_list(): void
    {
        // The other half of the test above: at that same instant a long-dated list is still current, so the
        // rejection there was the list going out of date and not merely the clock having moved.
        $signer = (new CertificateTrust())
            ->withClock(new FrozenClock(Timestamp::fromParts(self::AFTER_SHORT_LIST_EXPIRED)))
            ->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                $this->trustWith('crl-empty.pem'),
            );

        static::assertStringContainsString('WSSE Revocation Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_list_not_signed_by_a_trust_anchor_is_rejected(): void
    {
        // The forged list carries the real CA's issuer name, so it passes the coverage check and is stopped only
        // by the signature check. An unverified list is attacker-controlled input: a forged empty one would
        // un-revoke everything, and a forged populated one could revoke an honest signer.
        $this->assertRejectedBecause(
            'not signed by a configured trust anchor',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                $this->trustWith('crl-impostor.pem'),
            ),
        );
    }

    public function test_the_list_issuer_is_matched_by_the_same_rendering_certificates_use(): void
    {
        // The regression pin for the ordering bug this feature shipped with. Phpseclib's own DN_STRING joins the
        // encoded sequence least-specific first, while RFC 2253 (and so DistinguishedName) is most-specific
        // first, which made every multi-attribute issuer compare unequal and rejected every signer. The fixtures
        // carry a three-component DN precisely so a CN-only name cannot hide it again.
        $crl = CRL::load(file_get_contents(FIXTURE_DIR.'/certificates/revocation/crl-empty.pem'));

        $names = new DistinguishedNameParser();
        $listIssuer = $names->fromEncodedName($crl->getIssuerDN(CRL::DN_ARRAY));
        $certificateIssuer = $this->certificate('leaf.crt')->info()->issuerSerial()->issuer;

        static::assertTrue($listIssuer->equals($certificateIssuer));
        static::assertStringContainsString('CN=WSSE Revocation CA,', $listIssuer->toString());
    }

    public function test_a_list_stating_no_next_update_is_refused(): void
    {
        // A list with no nextUpdate can never be shown to be current, so it must not be read as valid forever.
        // Openssl refuses to emit one at all, so it is minted here with phpseclib, whose CRL writer omits it:
        // the same quirk that makes that writer unusable for the real fixtures.
        $writer = $this->crlWriter();
        $minted = $this->signedByRevocationCa($writer);
        static::assertArrayNotHasKey('nextUpdate', CRL::load($minted)->toArray()['tbsCertList']);

        $this->assertRejectedBecause(
            'past its nextUpdate',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                TrustStore::fromCertificates($this->certificate('ca.crt'))
                    ->withRevocationLists(new CertificateRevocationList($minted)),
            ),
        );
    }

    /**
     * @return iterable<string, list<string>>
     */
    public static function rolloverOrderings(): iterable
    {
        yield 'the superseded list first' => [['crl-empty.pem', 'crl-revoked.pem']];
        yield 'the current list first' => [['crl-revoked.pem', 'crl-empty.pem']];
    }

    /**
     * @param list<string> $lists
     */
    #[DataProvider('rolloverOrderings')]
    public function test_a_revoked_signer_stays_revoked_across_a_rollover_window(array $lists): void
    {
        // During an ordinary rollover both lists are inside their nextUpdate: the superseded one predates the
        // compromise and says nothing, the current one names the serial. Consulting whichever happens to come
        // first would make array position decide whether a revoked signer is accepted, so every current list
        // covering the issuer is read and any one of them naming the serial refuses.
        $this->assertRejectedBecause(
            'listed as revoked',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                TrustStore::fromCertificates($this->certificate('ca.crt'))->withRevocationLists(
                    ...array_map($this->revocationList(...), $lists),
                ),
            ),
        );
    }

    public function test_a_list_is_believed_when_its_issuer_is_not_the_first_anchor(): void
    {
        // Every anchor vouches for a list, not only whichever one the store happens to hold first. A two-partner
        // store is the ordinary shape, and deciding trust by array position would make revocation work for one
        // partner and refuse every message from the other, with a log blaming the list.
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('other-ca.crt'), $this->certificate('ca.crt'))
                ->withRevocationLists($this->revocationList('crl-empty.pem')),
        );

        static::assertStringContainsString('WSSE Revocation Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_a_list_stating_a_future_this_update_is_refused(): void
    {
        // A list issued later than now is not evidence about now. Reading it anyway would let a future-dated
        // empty list stand in for the one currently naming a compromised serial, which is the same un-revoking
        // the anchor-signature rule exists to stop, reached through the clock instead of the key. Openssl dates
        // a CRL at generation time and offers no way to postdate one, so it is minted here.
        $writer = $this->crlWriter();
        $writer->setThisDate('+30 days');
        $writer->setNextDate('+60 days');
        $minted = $this->signedByRevocationCa($writer);

        $this->assertRejectedBecause(
            'thisUpdate in the future',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                TrustStore::fromCertificates($this->certificate('ca.crt'))
                    ->withRevocationLists(new CertificateRevocationList($minted)),
            ),
        );
    }

    public function test_a_ca_registered_with_phpseclib_elsewhere_does_not_vouch_for_a_list(): void
    {
        // Phpseclib verifies a list against a process-wide CA store. An impostor with the real issuer's name,
        // registered there by unrelated code, must not be able to vouch for a list this trust store never
        // trusted, and the store must be handed back the way it was found.
        $key = RSA::createKey(2048);
        $impostor = new X509($key->getPublicKey());
        $realIssuer = X509::load(file_get_contents(FIXTURE_DIR.'/certificates/revocation/ca.crt'));
        $impostor->setSubjectDN($realIssuer->getSubjectDN(X509::DN_ARRAY));
        $impostor->setIssuerDN($realIssuer->getSubjectDN(X509::DN_ARRAY));
        $key->sign($impostor);

        $forged = new CRL();
        $forged->copySigningX509Attributes($impostor);
        $forged->setNextDate('+1 year');
        $key->sign($forged);

        X509::addCA($impostor);
        try {
            $this->assertRejectedBecause(
                'not signed by a configured trust anchor',
                fn (): mixed => (new CertificateTrust())->verify(
                    CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                    TrustStore::fromCertificates($this->certificate('ca.crt'))
                        ->withRevocationLists(new CertificateRevocationList((string) $forged)),
                ),
            );
            static::assertCount(1, X509::getCAs());
        } finally {
            X509::clearCAStore();
        }
    }

    public function test_a_list_that_cannot_be_parsed_is_refused(): void
    {
        // The fifth fail-closed arm, and the only one no test drove through the real code. It is reached from
        // six places, so a refactor letting any of them swallow the error instead would change the fail-closed
        // behaviour with a green suite.
        $this->assertRejectedBecause(
            'could not be read',
            fn (): mixed => (new CertificateTrust())->verify(
                CertificateChain::fromCertificates($this->certificate('leaf.crt')),
                TrustStore::fromCertificates($this->certificate('ca.crt'))
                    ->withRevocationLists(new CertificateRevocationList(
                        "-----BEGIN X509 CRL-----\nbm90LWEtY3Js\n-----END X509 CRL-----\n",
                    )),
            ),
        );
    }

    /**
     * The related worry, that a future phpseclib returning a DateTimeInterface instead of a formatted string
     * would make statedTime() read null for every list and silently refuse everything, needs no test of its own:
     * it cannot be silent. test_a_leaf_absent_from_a_current_list_is_accepted and
     * test_the_staleness_rule_does_not_reject_a_still_current_list both assert acceptance through that same
     * parse, so a format change turns them red rather than passing unnoticed.
     */
    public function test_an_unreadable_list_does_not_hide_a_usable_one(): void
    {
        // One unusable entry must not end the search. A store holding a broken list beside a good one still
        // reaches the good one, which is what keeps the arm above a refusal rather than a denial of service.
        $signer = (new CertificateTrust())->verify(
            CertificateChain::fromCertificates($this->certificate('leaf.crt')),
            TrustStore::fromCertificates($this->certificate('ca.crt'))->withRevocationLists(
                new CertificateRevocationList("-----BEGIN X509 CRL-----\nbm90LWEtY3Js\n-----END X509 CRL-----\n"),
                $this->revocationList('crl-empty.pem'),
            ),
        );

        static::assertStringContainsString('WSSE Revocation Leaf', $signer->subjectDistinguishedName()->toString());
    }

    public function test_enabling_revocation_with_no_lists_is_refused_at_configuration_time(): void
    {
        // A store that requires revocation but carries nothing to check against would reject every message.
        // Failing at configuration says so immediately instead of at the first response.
        $this->expectException(InvalidTrustStore::class);

        TrustStore::fromCertificates($this->certificate('ca.crt'))->withRevocationLists();
    }

    /**
     * @param callable(): mixed $attempt
     */
    private function assertRejectedBecause(string $reason, callable $attempt): void
    {
        try {
            $attempt();
        } catch (CertificateTrustException $exception) {
            static::assertStringContainsString($reason, $exception->getMessage());

            return;
        }

        static::fail('Expected a CertificateTrustException because '.$reason.'.');
    }

    private function trustWith(string $revocationList): TrustStore
    {
        return TrustStore::fromCertificates($this->certificate('ca.crt'))
            ->withRevocationLists($this->revocationList($revocationList));
    }

    private function certificate(string $file): Certificate
    {
        return Certificate::fromFile(FIXTURE_DIR.'/certificates/revocation/'.$file);
    }

    private function crlWriter(): CRL
    {
        $writer = new CRL();
        $writer->copySigningX509Attributes(
            X509::load(file_get_contents(FIXTURE_DIR.'/certificates/revocation/ca.crt')),
        );

        return $writer;
    }

    private function signedByRevocationCa(CRL $writer): string
    {
        $key = RSA::loadPrivateKey(file_get_contents(FIXTURE_DIR.'/certificates/revocation/ca.key'));
        $key->sign($writer);

        return (string) $writer;
    }

    private function revocationList(string $file): CertificateRevocationList
    {
        return CertificateRevocationList::fromFile(FIXTURE_DIR.'/certificates/revocation/'.$file);
    }
}
