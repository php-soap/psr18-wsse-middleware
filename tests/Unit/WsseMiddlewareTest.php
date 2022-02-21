<?php declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\Middleware;

use Http\Client\Common\Plugin;
use Http\Client\Common\PluginClient;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Mock\Client;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Soap\Psr18WsseMiddleware\WSSecurity\DigestMethod;
use Soap\Psr18WsseMiddleware\WSSecurity\Entry;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\BinarySecurityTokenIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyIdentifier\X509SubjectKeyIdentifier;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Certificate;
use Soap\Psr18WsseMiddleware\WSSecurity\KeyStore\Key;
use Soap\Psr18WsseMiddleware\WSSecurity\SignatureMethod;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Xml\Xpath\EnvelopePreset;
use VeeWee\Xml\Dom\Document;
use VeeWee\Xml\Dom\Xpath;

final class WsseMiddlewareTest extends TestCase
{
    private Certificate $publicKey;
    private Key $privateKey;
    private Client $mockClient;

    protected function setUp(): void
    {
        $this->publicKey = Certificate::fromFile(FIXTURE_DIR . '/certificates/wsse-client-public-key.pub');
        $this->privateKey = Key::fromFile(FIXTURE_DIR . '/certificates/wsse-client-private-key.pem');
        $this->mockClient = new Client(Psr17FactoryDiscovery::findResponseFactory());
    }

    private function configureMiddleware(array $incoming, array $outgoing = []): PluginClient
    {
        return new PluginClient($this->mockClient, [new WsseMiddleware($incoming, $outgoing)]);
    }

    public function test_it_is_a_middleware()
    {
        static::assertInstanceOf(Plugin::class, new WsseMiddleware([]));
    }

    public function test_it_adds_wsse_to_the_request_xml()
    {
        $client = $this->configureMiddleware([
            new Entry\Timestamp(),
            new Entry\BinarySecurityToken($this->publicKey),
            new Entry\Signature($this->privateKey, new BinarySecurityTokenIdentifier()),
        ]);

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $result = $client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        static::assertEquals($result, $response);

        // Check request structure:
        static::assertEquals($xpath->query('//soap:Header/wsse:Security')->count(), 1, 'No WSSE Security tag');
        static::assertEquals($xpath->query('//wsse:Security/wsse:BinarySecurityToken')->count(), 1, 'No  WSSE BinarySecurityToken tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature')->count(), 1, 'No DS Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo')->count(), 1, 'No DS SignedInfo Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod')->count(), 1, 'No DS SignedInfo CanonicalizationMethod Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:SignatureMethod')->count(), 1, 'No DS SignedInfo SignatureMethod Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference')->count(), 2, 'No DS SignedInfo Reference Signature tags');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform')->count(), 2, 'No DS SignedInfo Reference Transform Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod')->count(), 2, 'No DS SignedInfo Reference DigestMethod Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue')->count(), 2, 'No DS SignedInfo Reference DigestValue Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignatureValue')->count(), 1, 'No DS SignatureValue Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:KeyInfo')->count(), 1, 'No DS KeyInfo Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference')->count(), 1, 'No DS KeyInfo SecurityTokenReference Signature tag');
        static::assertEquals($xpath->query('//wsse:Security/wsu:Timestamp')->count(), 1, 'No WSU Timestamp tag');
        static::assertEquals($xpath->query('//wsse:Security/wsu:Timestamp/wsu:Created')->count(), 1, 'No WSU Created Timestamp tag');
        static::assertEquals($xpath->query('//wsse:Security/wsu:Timestamp/wsu:Expires')->count(), 1, 'No WSU Expires Timestamp tag');


        // Check defaults:
        static::assertEquals(
            XMLSecurityKey::RSA_SHA1,
            (string) $xpath->query('//ds:SignatureMethod')->item(0)->getAttribute('Algorithm')
        );
        static::assertEquals(
            strtotime((string) $xpath->query('//wsu:Created')->item(0)->nodeValue),
            strtotime((string) $xpath->query('//wsu:Expires')->item(0)->nodeValue) - 3600
        );
    }


    public function test_it_is_possible_to_configure_expiry_ttl()
    {
        $client = $this->configureMiddleware([
            new Entry\Timestamp(100),
        ]);

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        static::assertEquals(
            strtotime((string) $xpath->query('//wsu:Created')->item(0)->nodeValue),
            strtotime((string) $xpath->query('//wsu:Expires')->item(0)->nodeValue) - 100
        );
    }


    public function test_it_is_possible_to_sign_all_headers()
    {
        $client = $this->configureMiddleware([
            new Entry\Timestamp(),
            new Entry\BinarySecurityToken($this->publicKey),
            (new Entry\Signature($this->privateKey, new BinarySecurityTokenIdentifier()))
                ->withSignAllHeaders(true),
        ]);

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/wsa.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        static::assertEquals(6, $xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference')->count(), 'Not all headers are signed!');
        static::assertEquals(1, $xpath->query('//wsa:Action[@wsu:Id]')->count(), 'No signed WSA:Action.');
        static::assertEquals(1, $xpath->query('//wsa:To[@wsu:Id]')->count(), 'No signed WSA:To.');
        static::assertEquals(1, $xpath->query('//wsa:MessageID[@wsu:Id]')->count(), 'No signed WSA:MessageID.');
        static::assertEquals(1, $xpath->query('//wsa:ReplyTo[@wsu:Id]')->count(), 'No signed WSA:ReplyTo.');
    }


    public function test_it_is_possible_to_specify_another_digital_signature_and_digest_method()
    {
        $client = $this->configureMiddleware([
            new Entry\BinarySecurityToken($this->publicKey),
            (new Entry\Signature($this->privateKey, new BinarySecurityTokenIdentifier()))
                ->withSignatureMethod(SignatureMethod::RSA_SHA256)
                ->withDigestMethod(DigestMethod::SHA256),
        ]);

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        // Check defaults:
        static::assertEquals(
            SignatureMethod::RSA_SHA256->value,
            (string) $xpath->query('//ds:SignatureMethod')->item(0)->getAttribute('Algorithm')
        );
        static::assertEquals(
            DigestMethod::SHA256->value,
            (string) $xpath->query('//ds:DigestMethod')->item(0)->getAttribute('Algorithm')
        );
    }

    public function test_it_is_possible_to_specify_a_user_token()
    {
        $client = $this->configureMiddleware([
            new Entry\Timestamp(),
            new Entry\BinarySecurityToken($this->publicKey),
            (new Entry\Username('username'))
                ->withPassword('password')
                ->withDigest(false),
            (new Entry\Signature($this->privateKey, new BinarySecurityTokenIdentifier())),
        ]);

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        // Check defaults:
        static::assertEquals(3, $xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference')->count(), 'UserToken not signed!');
        static::assertEquals($xpath->query('//soap:Header/wsse:Security/wsse:UsernameToken')->count(), 1, 'No WSSE UsernameToken tag');
        static::assertEquals(1, $xpath->query('//wsse:Security/wsse:UsernameToken[@wsu:Id]')->count(), 'UserToken not signed!');
        static::assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Username')->count(), 1, 'No WSSE UserName tag');
        static::assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Password')->count(), 1, 'No WSSE Password tag');
        static::assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Nonce')->count(), 1, 'No WSSE Nonce tag');
        static::assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsu:Created')->count(), 1, 'No WSU Created tag');

        // Check values:
        static::assertEquals('username', (string) $xpath->query('//wsse:Username')->item(0)->nodeValue);
        static::assertEquals('password', (string) $xpath->query('//wsse:Password')->item(0)->nodeValue);
        static::assertEquals(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText',
            (string) $xpath->query('//wsse:Password')->item(0)->getAttribute('Type')
        );
    }

    public function test_it_is_possible_to_specify_a_user_token_with_digest()
    {
        $client = $this->configureMiddleware([
            (new Entry\Username('username'))
                ->withPassword('password')
                ->withDigest(true)
        ]);

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        // Check defaults:
        static::assertEquals($xpath->query('//soap:Header/wsse:Security/wsse:UsernameToken')->count(), 1, 'No WSSE UsernameToken tag');
        static::assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Username')->count(), 1, 'No WSSE UserName tag');
        static::assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Password')->count(), 1, 'No WSSE Password tag');
        static::assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Nonce')->count(), 1, 'No WSSE Nonce tag');
        static::assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsu:Created')->count(), 1, 'No WSU Created tag');

        // Check values:
        static::assertEquals('username', (string) $xpath->query('//wsse:Username')->item(0)->nodeValue);
        static::assertNotEquals('password', (string) $xpath->query('//wsse:Password')->item(0)->nodeValue);
        static::assertEquals(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest',
            (string) $xpath->query('//wsse:Password')->item(0)->getAttribute('Type')
        );
    }


    public function test_it_is_possible_to_encrypt_a_request()
    {
        $signCert = Certificate::fromFile(FIXTURE_DIR . '/certificates/wsse-client-x509.pem');
        $client = $this->configureMiddleware(
            [
                new Entry\Timestamp(),
                new Entry\BinarySecurityToken($this->publicKey),
                (new Entry\Signature($this->privateKey, new BinarySecurityTokenIdentifier())),
                (new Entry\Encryption($signCert, new X509SubjectKeyIdentifier($signCert)))
            ],
            [
                (new Entry\Decryption($this->privateKey))
            ]
        );

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request-with-head-and-body.xml');
        $soapResponse = file_get_contents(FIXTURE_DIR . '/soap/wsse-decrypt-response.xml');
        $this->mockClient->addResponse($response = new Response(200, [], $soapResponse));
        $response = $client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $encryptedXPath = $this->fetchEnvelopeXpath((string)$this->mockClient->getRequests()[0]->getBody());
        $decryptedXPath = $this->fetchEnvelopeXpath((string)$response->getBody());

        // Check Request headers:
        static::assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey')->count(), 1, 'No EncryptedKey tag');
        static::assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod')->count(), 1, 'No EncryptionMethod tag');
        static::assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo')->count(), 1, 'No KeyInfo tag');
        static::assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference')->count(), 1, 'No SecurityTokenReference tag');
        static::assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier')->count(), 1, 'No KeyIdentifier tag');
        static::assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/ds:Signature')->count(), 0, 'Signature is not encrypted');
        static::assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedData')->count(), 1, 'Signature is not encrypted');

        // Check request body:
        static::assertEquals($encryptedXPath->query('//soap:Body/xenc:EncryptedData')->count(), 1, 'No EncryptedData tag');
        static::assertEquals($encryptedXPath->query('//soap:Body/xenc:EncryptedData/xenc:EncryptionMethod')->count(), 1, 'No EncryptionMethod tag');
        static::assertEquals($encryptedXPath->query('//soap:Body/xenc:EncryptedData/xenc:CipherData')->count(), 1, 'No CipherData tag');
        static::assertEquals($encryptedXPath->query('//soap:Body/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue')->count(), 1, 'No CipherValue tag');

        // Check response headers:
        static::assertEquals($decryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedData')->count(), 0, 'Encrypted data was not decrypted');
        static::assertEquals($decryptedXPath->query('//soap:Header/wsse:Security/ds:Signature')->count(), 1, 'Signature could not be decrypted');

        // Check respone body:
        static::assertEquals($decryptedXPath->query('//soap:Body/xenc:EncryptedData')->count(), 0, 'Encrypted data was not decrypted');
    }

    private function fetchEnvelopeXpath(string $soapBody): Xpath
    {
        $document = Document::fromXmlString($soapBody);

        return $document->xpath(
            new EnvelopePreset($document),
            Xpath\Configurator\namespaces([
                'wsse' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
                'ds' => 'http://www.w3.org/2000/09/xmldsig#',
                'wsu' => 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
                'wsa' => 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
                'xenc' => 'http://www.w3.org/2001/04/xmlenc#',
                'dsig' => 'http://www.w3.org/2000/09/xmldsig#',
            ])
        );
    }
}
