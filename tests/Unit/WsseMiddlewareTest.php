<?php

namespace SoapTest\Psr18WsseMiddleware\Unit\Middleware;

use Http\Client\Common\Plugin;
use Http\Client\Common\PluginClient;
use Http\Discovery\Psr17FactoryDiscovery;
use Http\Mock\Client;
use Nyholm\Psr7\Request;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\TestCase;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Xml\Xpath\EnvelopePreset;
use VeeWee\Xml\Dom\Document;
use VeeWee\Xml\Dom\Xpath;

class WsseMiddlewareTest extends TestCase
{
    private PluginClient $client;
    private Client $mockClient;
    private WsseMiddleware $middleware;

    /***
     * Initialize all basic objects
     */
    protected function setUp(): void
    {
        $this->middleware = new WsseMiddleware(
            FIXTURE_DIR . '/certificates/wsse-client-private-key.pem',
            FIXTURE_DIR . '/certificates/wsse-client-public-key.pub'
        );
        $this->mockClient = new Client(Psr17FactoryDiscovery::findResponseFactory());
        $this->client = new PluginClient($this->mockClient, [$this->middleware]);
    }

    /**
     * @param callable(WsseMiddleware): WsseMiddleware $configurator
     */
    protected function configureMiddleware(callable $configurator)
    {
        $this->middleware = $configurator($this->middleware);
        $this->client = new PluginClient($this->mockClient, [$this->middleware]);
    }

    /**
     * @test
     */
    function it_is_a_middleware()
    {
        $this->assertInstanceOf(Plugin::class, $this->middleware);
    }

    /**
     * @test
     */
    function it_adds_Wsse_to_the_request_xml()
    {
        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $result = $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        $this->assertEquals($result, $response);

        // Check request structure:
        $this->assertEquals($xpath->query('//soap:Header/wsse:Security')->count(), 1, 'No WSSE Security tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:BinarySecurityToken')->count(), 1, 'No  WSSE BinarySecurityToken tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature')->count(), 1, 'No DS Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo')->count(), 1, 'No DS SignedInfo Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod')->count(), 1, 'No DS SignedInfo CanonicalizationMethod Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:SignatureMethod')->count(), 1, 'No DS SignedInfo SignatureMethod Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference')->count(), 2, 'No DS SignedInfo Reference Signature tags');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform')->count(), 2, 'No DS SignedInfo Reference Transform Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod')->count(), 2, 'No DS SignedInfo Reference DigestMethod Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue')->count(), 2, 'No DS SignedInfo Reference DigestValue Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:SignatureValue')->count(), 1, 'No DS SignatureValue Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:KeyInfo')->count(), 1, 'No DS KeyInfo Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference')->count(), 1, 'No DS KeyInfo SecurityTokenReference Signature tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsu:Timestamp')->count(), 1, 'No WSU Timestamp tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsu:Timestamp/wsu:Created')->count(), 1, 'No WSU Created Timestamp tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsu:Timestamp/wsu:Expires')->count(), 1, 'No WSU Expires Timestamp tag');


        // Check defaults:
        $this->assertEquals(
            XMLSecurityKey::RSA_SHA1,
            (string) $xpath->query('//ds:SignatureMethod')->item(0)->getAttribute('Algorithm')
        );
        $this->assertEquals(
            strtotime((string) $xpath->query('//wsu:Created')->item(0)->nodeValue),
            strtotime((string) $xpath->query('//wsu:Expires')->item(0)->nodeValue) - 3600
        );
    }

    /**
     * @test
     */
    function it_is_possible_to_configure_expiry_ttl()
    {
        $this->configureMiddleware(
            fn (WsseMiddleware $middleware) => $middleware->withTimestamp(100)
        );

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        $this->assertEquals(
            strtotime((string) $xpath->query('//wsu:Created')->item(0)->nodeValue),
            strtotime((string) $xpath->query('//wsu:Expires')->item(0)->nodeValue) - 100
        );
    }

    /**
     * @test
     */
    function it_is_possible_to_sign_all_headers()
    {
        $this->configureMiddleware(
            fn (WsseMiddleware $middleware) => $middleware->withAllHeadersSigned()
        );

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/wsa.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        $this->assertEquals(6, $xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference')->count(), 'Not all headers are signed!');
        $this->assertEquals(1, $xpath->query('//wsa:Action[@wsu:Id]')->count(), 'No signed WSA:Action.');
        $this->assertEquals(1, $xpath->query('//wsa:To[@wsu:Id]')->count(), 'No signed WSA:To.');
        $this->assertEquals(1, $xpath->query('//wsa:MessageID[@wsu:Id]')->count(), 'No signed WSA:MessageID.');
        $this->assertEquals(1, $xpath->query('//wsa:ReplyTo[@wsu:Id]')->count(), 'No signed WSA:ReplyTo.');
    }

    /**
     * @test
     */
    function it_is_possible_to_specify_another_digital_signature_method()
    {
        $this->configureMiddleware(
            fn (WsseMiddleware $middleware) => $middleware->withDigitalSignMethod(XMLSecurityKey::RSA_SHA256)
        );

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        // Check defaults:
        $this->assertEquals(
            XMLSecurityKey::RSA_SHA256,
            (string) $xpath->query('//ds:SignatureMethod')->item(0)->getAttribute('Algorithm')
        );
    }

    /**
     * @test
     */
    function it_is_possible_to_specify_a_user_token()
    {
        $this->configureMiddleware(
            fn (WsseMiddleware $middleware) => $middleware->withUserToken('username', 'password', false)
        );

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        // Check defaults:
        $this->assertEquals(3, $xpath->query('//wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference')->count(), 'UserToken not signed!');
        $this->assertEquals($xpath->query('//soap:Header/wsse:Security/wsse:UsernameToken')->count(), 1, 'No WSSE UsernameToken tag');
        $this->assertEquals(1, $xpath->query('//wsse:Security/wsse:UsernameToken[@wsu:Id]')->count(), 'UserToken not signed!');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Username')->count(), 1, 'No WSSE UserName tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Password')->count(), 1, 'No WSSE Password tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Nonce')->count(), 1, 'No WSSE Nonce tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsu:Created')->count(), 1, 'No WSU Created tag');

        // Check values:
        $this->assertEquals('username', (string) $xpath->query('//wsse:Username')->item(0)->nodeValue);
        $this->assertEquals('password', (string) $xpath->query('//wsse:Password')->item(0)->nodeValue);
        $this->assertEquals(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText',
            (string) $xpath->query('//wsse:Password')->item(0)->getAttribute('Type')
        );
    }

    /**
     * @test
     */
    function it_is_possible_to_specify_a_user_token_with_digest()
    {
        $this->configureMiddleware(
            fn (WsseMiddleware $middleware) => $middleware->withUserToken('username', 'password', true)
        );

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xpath = $this->fetchEnvelopeXpath($soapBody);

        // Check defaults:
        $this->assertEquals($xpath->query('//soap:Header/wsse:Security/wsse:UsernameToken')->count(), 1, 'No WSSE UsernameToken tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Username')->count(), 1, 'No WSSE UserName tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Password')->count(), 1, 'No WSSE Password tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsse:Nonce')->count(), 1, 'No WSSE Nonce tag');
        $this->assertEquals($xpath->query('//wsse:Security/wsse:UsernameToken/wsu:Created')->count(), 1, 'No WSU Created tag');

        // Check values:
        $this->assertEquals('username', (string) $xpath->query('//wsse:Username')->item(0)->nodeValue);
        $this->assertNotEquals('password', (string) $xpath->query('//wsse:Password')->item(0)->nodeValue);
        $this->assertEquals(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest',
            (string) $xpath->query('//wsse:Password')->item(0)->getAttribute('Type')
        );
    }

    /**
     * @test
     */
    function it_is_possible_to_encrypt_a_request()
    {
        $this->configureMiddleware(
            fn (WsseMiddleware $middleware) => $middleware
                ->withEncryption(FIXTURE_DIR . '/certificates/wsse-client-x509.pem')
                ->withServerCertificateHasSubjectKeyIdentifier(true)
        );

        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request-with-head-and-body.xml');
        $soapResponse = file_get_contents(FIXTURE_DIR . '/soap/wsse-decrypt-response.xml');
        $this->mockClient->addResponse($response = new Response(200, [], $soapResponse));
        $response = $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $encryptedXPath = $this->fetchEnvelopeXpath((string)$this->mockClient->getRequests()[0]->getBody());
        $decryptedXPath = $this->fetchEnvelopeXpath($response->getBody());

        // Check Request headers:
        $this->assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey')->count(), 1, 'No EncryptedKey tag');
        $this->assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey/xenc:EncryptionMethod')->count(), 1, 'No EncryptionMethod tag');
        $this->assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo')->count(), 1, 'No KeyInfo tag');
        $this->assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference')->count(), 1, 'No SecurityTokenReference tag');
        $this->assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedKey/dsig:KeyInfo/wsse:SecurityTokenReference/wsse:KeyIdentifier')->count(), 1, 'No KeyIdentifier tag');
        $this->assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/ds:Signature')->count(), 0, 'Signature is not encrypted');
        $this->assertEquals($encryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedData')->count(), 1, 'Signature is not encrypted');

        // Check request body:
        $this->assertEquals($encryptedXPath->query('//soap:Body/xenc:EncryptedData')->count(), 1, 'No EncryptedData tag');
        $this->assertEquals($encryptedXPath->query('//soap:Body/xenc:EncryptedData/xenc:EncryptionMethod')->count(), 1, 'No EncryptionMethod tag');
        $this->assertEquals($encryptedXPath->query('//soap:Body/xenc:EncryptedData/xenc:CipherData')->count(), 1, 'No CipherData tag');
        $this->assertEquals($encryptedXPath->query('//soap:Body/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue')->count(), 1, 'No CipherValue tag');

        // Check response headers:
        $this->assertEquals($decryptedXPath->query('//soap:Header/wsse:Security/xenc:EncryptedData')->count(), 0, 'Encrypted data was not decrypted');
        $this->assertEquals($decryptedXPath->query('//soap:Header/wsse:Security/ds:Signature')->count(), 1, 'Signature could not be decrypted');

        // Check respone body:
        $this->assertEquals($decryptedXPath->query('//soap:Body/xenc:EncryptedData')->count(), 0, 'Encrypted data was not decrypted');
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
