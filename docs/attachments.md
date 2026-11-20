# Attachment security

[← Back to the deep dives](../README.md#deep-dives)

Signing, verifying, encrypting and decrypting SOAP attachments as first-class parts of the message, under the
same key material as the body.

This is the [WSS SOAP Messages with Attachments (SwA) Profile 1.1](https://docs.oasis-open.org/wss-m/wss/v1.1.1/os/wss-SwAProfile-v1.1.1-os.html).
You most often meet it because a peer's WS-SecurityPolicy requires it: `sp:Attachments` under `sp:SignedParts`
or `sp:EncryptedParts`, which is what Apache CXF and WSS4J emit and enforce.

## What you need

Attachment handling itself lives in a separate package, so cryptography and MIME stay independent:

```bash
composer require php-soap/psr18-attachments-middleware
```

Version **0.12.0** or later. This package names it under `suggest`, never `require`: nothing about installing
WS-Security pulls in attachment handling, and nothing about using attachments pulls in cryptography.

## Wiring

```php
use Http\Client\Common\PluginClient;
use Phpro\ResourceStream\Factory\FileStream;
use Soap\Psr18AttachmentsMiddleware\Attachment\Attachment;
use Soap\Psr18AttachmentsMiddleware\Middleware\AttachmentsMiddleware;
use Soap\Psr18AttachmentsMiddleware\Multipart\AttachmentType;
use Soap\Psr18AttachmentsMiddleware\Storage\AttachmentStorage;
use Soap\Psr18Transport\Psr18Transport;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\AttachmentParts;
use Soap\Psr18WsseMiddleware\WSSecurity\{Inbound, Keys, Outbound, Part, SecurityProfile, Signing};
use Soap\Psr18WsseMiddleware\WsseMiddleware;
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

// Keep this somewhere central: it is how you add and read attachments per call.
$attachments = new AttachmentStorage();

$transport = Psr18Transport::createForClient(
    new PluginClient($yourPsr18Client, [
        // WSSE first: it must see plain XML on the way out and a split multipart on the way back.
        new WsseMiddleware(
            new SecurityProfile(),
            outbound: [
                new Outbound\Timestamp(),
                // Sign first, so the digest covers the plaintext attachment.
                (new Outbound\Signature(new Signing\Asymmetric($clientCertificate)))
                    ->withAttachments(AttachmentParts::request($attachments, ExternalPartCoverage::Complete)),
                (new Outbound\Encryption(new Keys\GeneratedSessionKey($recipientCertificate)))
                    ->withParts([Part::body()])
                    ->withAttachments(AttachmentParts::request($attachments, ExternalPartCoverage::Content)),
            ],
            inbound: [
                // Decrypt first, so the signature is verified against the plaintext.
                (new Inbound\Decrypt($privateKey))
                    ->withAttachments(AttachmentParts::response($attachments, ExternalPartCoverage::Complete)),
                (new Inbound\VerifySignature($trustStore))
                    ->withAttachments(AttachmentParts::response($attachments, ExternalPartCoverage::Complete)),
                new Inbound\ValidateTimestamp(),
            ],
        ),
        new AttachmentsMiddleware($attachments, AttachmentType::Swa),
    ])
);

// Attachments are added per call, before the request goes out.
$attachments->requestAttachments()->add(Attachment::cid(
    uri: 'invoice@example.com',
    name: 'invoice',
    filename: 'invoice.pdf',
    content: FileStream::create('/path/to/invoice.pdf', FileStream::READ_MODE),
));

$response = $client->request('Foo', $payload);

// Decrypted on the way in, with the original media type restored.
foreach ($attachments->responseAttachments() as $attachment) {
    $attachment->content->copyTo(
        FileStream::create('/tmp/'.$attachment->filename, FileStream::WRITE_MODE),
    );
}
```

Two ordering rules, and neither is cosmetic:

- **`WsseMiddleware` before `AttachmentsMiddleware`.** In a `PluginClient` the first plugin is the outermost,
  so this gives WSSE the request before it is packed into a multipart body and the response after it is split
  back out. The other order shows WSSE a multipart blob it cannot read.
- **Sign then encrypt outbound, decrypt then verify inbound.** The same rule the body already follows. The
  `ds:Reference` keeps naming `cid:invoice@example.com` while the part behind it becomes ciphertext, so inbound
  the plaintext has to be restored before the digest is checked. Any other inbound order fails.

Use `AttachmentParts::request()` on outbound blocks and `AttachmentParts::response()` on inbound ones. The two
collections are kept apart deliberately: an outbound block must never reach the parts that arrived with a
response.

## MTOM needs nothing extra

SwA and MTOM/XOP are one mechanism here. Both put the bytes in a MIME part addressed by `cid:`, and this
feature encrypts and signs MIME parts addressed by `cid:`. Nothing branches on `AttachmentType`.

One thing does need the extra, and it is not this feature: a peer that also moves its *cipher* bytes into MIME
parts. See [Cipher bytes in MIME parts](#cipher-bytes-in-mime-parts) below, which is where the "nothing extra"
stops holding.

That works because the attachments middleware owns both the attachment and the `xop:Include` tag and never
inlines base64. Outbound, the encoder puts the plaintext in the storage and an `<xop:Include href="cid:..."/>`
in the XML; this package encrypts the part in the storage and leaves the include alone. Inbound, the response
builder fills the storage with the ciphertext parts, this package decrypts them, and the engine then resolves
the include to the decrypted attachment. Decoding happens after the transport, and therefore after this
middleware, which is why nothing has to move.

**Measured, not argued.** The interop suite runs all four directions twice, once packaged as SwA and once as
MTOM, against a WSS4J peer: each side signs and the other verifies, each side encrypts and the other decrypts.
The MTOM encryption case also reads the part as it crossed the wire and asserts it was ciphertext there, which
is what would fail if the peer resolved the `xop:Include` before its security interceptor ran.

**MTOM here means SOAP 1.2.** The attachments middleware writes `start-info="application/soap+xml"` into an
MTOM `Content-Type` whatever the envelope says, and a SOAP 1.1 XOP package is one whose `start-info` is
`text/xml`, so a peer reading a SOAP 1.1 envelope out of an MTOM package refuses it before any security
processing happens. Pair `AttachmentType::Mtom` with a SOAP 1.2 envelope.

**One guard runs the other way.** Encrypting an *element* that contains an `xop:Include` is refused. The
ciphertext would cover the pointer while the file itself travelled in the clear in its own part, and the
message would still satisfy a policy check for that element being encrypted. Encrypting the *part* an include
points at is the supported path, and that is what `withAttachments()` does.

## Cipher bytes in MIME parts

This is a different mechanism from everything above, and it needs its own block. A peer may put the bytes of
an `xenc:CipherValue` or a `wsse:BinarySecurityToken` in a MIME part and leave an `xop:Include` behind, which
skips the 33% base64 costs. WSS4J calls it `storeBytesInAttachment`.

**It is not an attachment feature and it is not negotiated.** It applies to every encrypted message, whether
or not attachments are involved, and no WS-SecurityPolicy assertion expresses it. It is also not exotic:

- Apache CXF turns it on by default whenever MTOM is enabled, along with `expandXopInclude`.
- .NET/WCF and Metro do it to any large encrypted content unconditionally. Apache's
  [CXF-6409](https://issues.apache.org/jira/browse/CXF-6409) exists because CXF itself could not read .NET and
  Metro messages for exactly this reason.

So this arrives whether or not anyone chose it. Because the peers switch on a size threshold, one message
routinely mixes both shapes: a small wrapped key stays inline base64 while the body's cipher value moves to a
part.

Inbound, put `Inbound\ResolveOptimizedBytes` first in the list and everything after it sees an ordinary
message. Outbound, `Outbound\Encryption::withOptimizedCipherBytes()` emits the same shape. Both are covered
in the block references: [inbound](inbound-blocks.md#inbound-resolveoptimizedbytes) and
[outbound](outbound-blocks.md#outbound-encryption).

```php
$inbound = [
    new Inbound\ResolveOptimizedBytes(
        AttachmentParts::response($attachmentStorage, ExternalPartCoverage::Content),
    ),
    new Inbound\Decrypt($privateKey),
    // ...
];
```

Measured against a live WSS4J peer in both directions, including a `wsse:BinarySecurityToken` moved the same
way, so the packaging is not read off the sources.

## Wire format

Next to an encrypted Body, an encrypted attachment looks like this:

```xml
<wsse:Security>
  <xenc:EncryptedKey>
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"/>
    <ds:KeyInfo>...</ds:KeyInfo>
    <xenc:CipherData><xenc:CipherValue>...</xenc:CipherValue></xenc:CipherData>
    <xenc:ReferenceList>
      <xenc:DataReference URI="#EncData-body"/>
      <xenc:DataReference URI="#EncData-attachment"/>
    </xenc:ReferenceList>
  </xenc:EncryptedKey>
  <xenc:EncryptedData wsu:Id="EncData-attachment"
                      Type="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Only"
                      MimeType="application/pdf">
    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
    <xenc:CipherData>
      <xenc:CipherReference URI="cid:invoice@example.com">
        <xenc:Transforms>
          <ds:Transform Algorithm="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Ciphertext-Transform"/>
        </xenc:Transforms>
      </xenc:CipherReference>
    </xenc:CipherData>
  </xenc:EncryptedData>
</wsse:Security>
```

The MIME part keeps its `Content-ID`, its `Content-Type` becomes `application/octet-stream`, and its body is
the raw `IV || ciphertext || tag`: unencoded, because the MIME layer carries the bytes and nothing has to escape
them. The original media type travels on `@MimeType` so the receiver can restore it. This is what Apache WSS4J
emits, which is what CXF and Metro peers expect.

**One `xenc:EncryptedKey`, always.** Its single `xenc:ReferenceList` names the in-document parts and the
attachment parts together, so all of them are under one session key. That is why `withAttachments()` sits on
the same `Outbound\Encryption` block rather than being a block of its own: a second block would emit a second
key, which a receiver refuses.

Sharing that key with a `Signature` block works too, and changes the shape: the `xenc:ReferenceList` moves out of
the `xenc:EncryptedKey` and each `xenc:EncryptedData`, attachments included, names the key with an
`EncryptedKeySHA1` identifier. See
[where the reference list goes](outbound-blocks.md#outbound-encryption). The interop harness covers it.

A signed attachment adds a reference to the same `ds:Signature` as the body's:

```xml
<ds:Reference URI="cid:invoice@example.com">
  <ds:Transforms>
    <ds:Transform Algorithm="http://docs.oasis-open.org/wss/oasis-wss-SwAProfile-1.1#Attachment-Content-Signature-Transform"/>
  </ds:Transforms>
  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  <ds:DigestValue>...</ds:DigestValue>
</ds:Reference>
```

One signature covering body and attachments together, which is the shape a far-side `sp:SignedParts` policy is
checked against. There is no transfer-encoding step: the attachments middleware sends
`Content-Transfer-Encoding: binary`, so the bytes on the wire are the bytes hashed. The URI is the part's
`cid:` verbatim, which binds each digest to one specific part: swapping two attachments is a digest mismatch
rather than a substitution nobody notices.

**The digest is over the content transform's output, which is the identity only for binary parts.** The
transform branches three ways on the media type:

| The part's media type | What is digested |
|---|---|
| `text/xml`, `application/xml`, a `+xml` subtype of `application` or `image` | The content canonicalized with exclusive C14N, no prefix list, comments omitted. The whole document node, so a processing instruction outside the root is covered too |
| Any other `text/*` | The content with a CR, an LF and a CRLF each normalized to a CRLF |
| Everything else | The octets exactly as they travel |

A signature never modifies the part; only the digest is taken over the transformed form. Encryption is the one
operation that does replace it, with the sealed bytes described above. Text is
normalized because MIME lets an intermediary rewrite line endings in text and not in binary, and XML because
one tree has more than one spelling.

All three are pinned against a live peer in both directions, with shapes whose transformed form differs from
their octets. Removing either canonicalization makes the peer reject the signature.

## How much of a part a protection covers

The profile has two coverages, and which one your peer wants is decidable from its WSDL. Read
`sp:SignedParts` and `sp:EncryptedParts`:

| The peer's WSDL says | Configure |
|---|---|
| `<sp:SignedParts><sp:Attachments/></sp:SignedParts>` | `ExternalPartCoverage::Complete` |
| `<sp:Attachments><sp13:ContentSignatureTransform/></sp:Attachments>` | `ExternalPartCoverage::Content` |
| `<sp:EncryptedParts><sp:Attachments/></sp:EncryptedParts>` | Either satisfies the policy. Use `Content` outbound, and be ready to accept `Complete` inbound |
| Nothing about attachments | Neither. Do not register attachment parts on the blocks |

**A bare `<sp:Attachments/>` means `Complete`.** Content-only is the opt-in, not the default:
`sp13:ContentSignatureTransform` is what asks for it, and the AS4 and eDelivery profiles are the population
that sets it. CXF picks `Complete` for anything else and enforces it on the way in, so a signature covering
content only does not satisfy a default policy.

You choose where the adapter is built:

```php
use Soap\Psr18WsseMiddleware\XmlSecurity\ExternalPartCoverage;

// A bare <sp:Attachments/> in the peer's SignedParts.
(new Outbound\Signature(new Signing\Asymmetric($clientCertificate)))
    ->withAttachments(AttachmentParts::request($attachments, ExternalPartCoverage::Complete));

// EncryptedParts is satisfied by either, so content-only is the cheaper choice.
(new Outbound\Encryption(new Keys\GeneratedSessionKey($recipientCertificate)))
    ->withParts([Part::body()])
    ->withAttachments(AttachmentParts::request($attachments, ExternalPartCoverage::Content));

// A default-configured CXF sender encrypts Complete, so accept that on the way in.
(new Inbound\Decrypt($privateKey))
    ->withAttachments(AttachmentParts::response($attachments, ExternalPartCoverage::Complete));
```

The asymmetry is not an oversight: it is what the two policy validators require. Building two adapters is the
supported way to express it, since they are cheap immutable values.

**There is no default: the coverage is required.** It is not a preference to be nudged by a sensible
starting value. Your peer's policy decides it, both wrong answers are refused by that peer, and a default
would let the decision be skipped by somebody who never opened the WSDL. The table above is the whole rule.

On an encrypting block the answer is always `Content`, since that is the only coverage this package emits
and a peer never validates an encryption's scope. Everywhere else, read the policy.

**Inbound, the coverage you configure is a requirement rather than a hint.** A `Complete` adapter on
`VerifySignature` refuses a reference declaring the content transform, and `Decrypt` refuses the wrong
`@Type` before any decryption. A peer may not decide to cover less than it was asked to. This mirrors what
`CryptoCoverageUtil.checkAttachmentsCoverage()` does to us in the other direction.

### What a complete coverage digests

The part's canonical MIME header block, followed by whatever the content transform produced for its media
type. No blank line separates them: the transformed bytes follow the last header's CRLF directly. The header
block itself is never put through the transform.

```text
Content-Disposition:attachment;filename="invoice.pdf";name="invoice"\r\n
Content-ID:<invoice@example.com>\r\n
Content-Type:application/pdf\r\n
<the attachment bytes>
```

Four headers are covered, ascending by name: `Content-Disposition`, `Content-ID`, `Content-Location` and
`Content-Type`. The profile names a fifth, `Content-Description`, and this package refuses a part carrying
one. Measured against a live peer: it is the only one of the five that a peer canonicalizes *without*
stripping the whitespace a MIME parser leaves after the colon, so what it digests depends on whether its own
parser trimmed that separator. Nothing this side can compute predicts that, and neither this package nor the
peer emits the header, so refusing costs nothing a caller did not add deliberately. `Content-Transfer-Encoding` is not among them, so it is
neither signed nor encrypted even though the multipart carries it. Values are stripped of leading
whitespace, and a value carrying parameters is rewritten with its essence and parameter names lowercased, its
parameters sorted, and their values quoted. The values of the case-insensitive parameters are lowercased too,
those being `charset`, `creation-date`, `filename`, `modification-date`, `padding`, `read-date`, `size` and
`type`, so a `filename="Invoice.PDF"` is digested as `filename="invoice.pdf"`. When the header set carries no `Content-Type` at all,
`text/plain;charset="us-ascii"` is substituted, which is what a peer does with the same absence. An
`Attachment` always describes its media type, so that substitution is reachable only through a header set
that came out of a peer's ciphertext or out of an adapter you wrote yourself.

A header set carrying the same profile header twice is refused. Canonicalization has no defined answer for
it, and a peer's sorted map silently keeps one of the two, so agreeing on a digest would be luck.

This is pinned against Apache WSS4J rather than read off the profile: the interop harness has the oracle
report the header block it computed and compares it against the one this package composed for the same part.

### Header forms this package refuses rather than guesses at

| Construct | Detected by |
|---|---|
| A `Content-Description` at all | the header being present |
| A comment | an unquoted `(` in one of the four remaining headers |
| An RFC 2184 continued or charset-tagged parameter | a parameter name containing `*` |
| A parameter with no `=`, or an empty value | the parameter itself |

Each needs a decoder whose output has to agree with the peer byte for byte, and nothing short of a message
from that peer proves it does. A refusal cannot produce a wrong digest; a guess can, and a wrong digest is
the failure with no diagnostic attached. Outbound this is a configuration error naming the header. Inbound it
collapses into the uniform verification failure like anything else.

Opened octets are read back with the same caps a peer applies: at most 100 headers and 1000 characters per
line before the blank line. They bound a scan over decrypted attacker-supplied bytes, and a legitimate peer
never trips them.

## What is refused, and why

| Case | Behaviour |
|---|---|
| An XML attachment whose octets are not a document, or that carries a doctype | Refused. There is no node-set to canonicalize, so there is no digest to compute. A peer refuses a doctype in an attachment too, so this is agreement rather than a restriction invented here |
| An attachment whose stream reads zero bytes | Refused on both outbound operations. Signing nothing produces a digest over no file, and encrypting nothing ships an empty file that passes every structural check on the far side. A stream that cannot rewind reads this way too |
| Encrypting an element that is or contains an `xop:Include` | Refused. See the MTOM section above |
| Signing an element containing an `xop:Include` whose `cid:` you did not register | Refused. The signature would cover the pointer while the file travels unprotected, and the message would still satisfy a policy check for that element being signed |
| Verifying a signature over an element containing an `xop:Include` that the same signature does not also digest | Refused. Being supplied says the part arrived, not that the signature vouches for it, so the question asked is what this `ds:SignedInfo` covers |
| A security value describing its content two ways at once (text beside an `xop:Include`, two of them, one nested deeper, one naming nothing) | Refused rather than read either way. Whichever reading was picked, the other is the one an attacker would have chosen |
| A registered attachment that no `ds:Reference` covers | Refused. Registering parts on `VerifySignature` is the requirement that they be signed |
| An encrypted attachment when none are registered on `Decrypt` | Refused, never skipped. Otherwise the message reads as decrypted while your code holds ciphertext |
| A `cid:` reference naming a part you did not supply | Refused. Never resolved, never fetched, under any circumstance |
| Emitting `Attachment-Complete` ciphertext | Refused. No policy can require it, because a peer validates the coverage of a signature and never of an encryption, so content-only always satisfies the far side. Accepting it inbound is supported |
| A header carrying a comment or a continued parameter, under a complete coverage | Refused rather than canonicalized by guesswork. See the table above |
| The same profile header twice, under a complete coverage | Refused. Canonicalization has no defined answer, and a peer silently keeps one of the two |
| Restored headers naming a different `Content-ID` than the part they arrived in | Refused. The `Content-ID` is how a reference bound the digest to this part, so letting the ciphertext rewrite it would undo that binding |
| Opened octets carrying no blank line, or exceeding the header caps | Refused before the bytes are handed anywhere |
| A cipher reference declaring no transform, several, or the wrong one | Refused before any decryption |
| A data-encryption method outside the profile's allow-list | Refused. An external part gets the same allow-list as an in-document one, CBC refusal included |
| A registered attachment that arrived unencrypted | Refused. Registering parts on `Decrypt` is the requirement that they arrive encrypted, so one that travelled in the clear beside encrypted ones refuses the message |
| A registered attachment a signature or an encryption did not cover | Refused outbound. Both engines report what they actually covered, so a replaceable signer or encryptor that returns less than it was handed cannot leave you sending a part you configured as protected |
| Opened octets carrying a header line with no colon | Refused rather than skipped. A peer restores what it split, not what could be made sense of |
| `replace()` handed a reference no attachment answers | Refused. The list it receives is the list it was built from |
| An attachments middleware older than 0.12.0 | Refused where the adapter is built, naming the package and the version, since composer constrains none of it |
| Two attachments sharing a `Content-ID` | Refused. One reference must address one part |

Inbound, every one of these collapses into the same `SecurityFault` as the rest of the inbound path, so the
attachment path is no more of an oracle than the body's. Outbound failures do state a reason, since nothing
about your own outbound message is a secret from you. A refusal about the message is `SigningFailed` or
`EncryptionFailed`; a refusal about your configuration or your headers carries its own type, one of
`UnsupportedAttachmentCoverage`, `UnsupportedAttachmentHeaderForm`, `UnsupportedAttachmentsVersion` or
`UnknownAttachment`.

## Limits

- **Whole parts are buffered.** The cipher takes and returns strings, so an attachment is held in memory around
  twice at peak. That matches what the attachments middleware already implies by building the multipart body in
  memory. Attachments comfortably smaller than available memory are the supported case.

  This applies to cipher bytes in MIME parts too, and it bites harder there, because size is the only reason a
  peer sends that shape at all: the part is read whole, base64-encoded, and put in the document, so peak is
  nearer three times its size. Streaming it would not help on its own. The whole decryption path is
  string-based, from the cipher value through `CipherText` to the cipher itself, so the document is not the
  bottleneck and this is a property of the engine rather than of this feature.
- **Emitting `Attachment-Complete` ciphertext is not implemented.** Signing, verification and decryption all
  support the complete coverage; outbound encryption does not, and no policy can require it. What it would
  buy is hiding the filename and media type from an intermediary that terminates TLS, which content-only
  leaves readable in the MIME headers. Nobody has asked for it.
- **Emitting a `wsse:BinarySecurityToken` into a MIME part is not implemented.** WSS4J moves the token's bytes
  out too when `storeBytesInAttachment` is on, and this package reads that shape but does not produce it. A
  certificate is around 1.5 KB, so the saving is a few hundred bytes, and it collides with the default signed
  parts: `Part::securityHeaderContents()` covers the token, and signing an element whose content is a pointer
  is refused unless the same signature covers those bytes. WSS4J resolves that by always expanding a signed
  token; matching it would mean an exception to the coverage rule for one element, to save nothing.
- **An XML attachment must be a well-formed document with no doctype.** Its content is canonicalized before
  digesting, so there has to be something to canonicalize. Both limits match what a peer does with the same
  bytes.
- **A `Content-ID` should stay alphanumeric for a WSS4J peer.** One containing `+` or `%` draws "Attachment
  not found" from Apache WSS4J, which reads a `cid:` reference with a form decoder rather than a URI one and
  so turns a `+` into a space. It emits those references unencoded, so the same id breaks its own round trip
  and no peer can be using one; the exposure is only an id you choose here. The generated ids are
  alphanumeric, so this reaches you only if you name attachments yourself.
- **WCF and .NET cannot be the peer for SwA.** There is no SwA support in WCF, only MTOM. A .NET peer that
  wants *attachment* security is not a case this feature serves. It is very much the peer for the section
  below, though: cipher bytes in MIME parts is what .NET does by default.

## Writing your own adapter

`AttachmentParts` is a thin adapter over one storage, and the seam it implements is public:

```php
interface ExternalParts
{
    public function coverage(): ExternalPartCoverage;
    public function collect(): ExternalPartList;
    public function collectSealed(): ExternalPartList;
    public function add(ResourceStream $content, string $mimeType, string $name): ExternalPart;
    public function replace(ExternalPartList $parts): void;
}
```

Implement it if your attachments live somewhere else. Five contract points matter:

- **`coverage()` says how much of a part your compositions cover**, and the blocks read it: it decides both
  the transform they declare and what they expect from a peer. Return `ExternalPartCoverage::Content` unless
  you compose the canonical header block yourself.
- **`collect()` returns the parts a signature covers.** The content goes in `ExternalPart::$content` and,
  under a `Complete` coverage, the canonical header block goes in `ExternalPart::$digestPrefix`. Do not
  concatenate the two yourself: the engine applies the content transform to `$content` and prepends
  `$digestPrefix` to the result, which is the order a peer composes them in. Joining them first puts the
  header block through the transform, and for an XML part that means handing a canonicalizer a header block
  to parse.
- **`add()` adds a part the message did not arrive with**, and returns it carrying the reference that now
  addresses it. The reference is yours to choose: nothing above this decides what addresses a part, so an
  adapter over something other than MIME need not produce anything resembling a Content-ID. The `$name` goes
  the other way, because it is the one thing about the part you cannot work out: the bytes mean something to
  whoever handed them over and nothing to you. Several parts may share a name; the reference is what tells
  them apart. Only `Outbound\Encryption::withOptimizedCipherBytes()` reaches this, and only when a caller
  asked for it.
- **`collectSealed()` returns the same parts with an empty `$digestPrefix`**, which a cipher seals on the way
  out and opens on the way in. A `xenc:CipherReference` addresses the MIME part, so what sits there is the
  part's own octets whatever the coverage says a signature covers. Return `collect()` if you compose nothing.
- **`collect()` may be called more than once per message, so rewind on every collect.** Sign-then-encrypt
  collects twice: the signature digests the plaintext, then encryption seals the same plaintext. The engine
  rewinds each part before reading it as well, so a spent stream is recovered rather than sealed empty, but do
  not lean on that: it is defence in depth, and a stream that cannot rewind reads as zero bytes and is refused.
- **`replace()` fully replaces the parts it is handed, matched by reference, and touches nothing else.**
  Inbound it receives only the parts an `xenc:EncryptedData` actually named. An attachment that arrived in the
  clear is absent from that list and must be left as it is rather than dropped, though with the shipped
  adapter the block has already refused the message by then: see the refusal table.
