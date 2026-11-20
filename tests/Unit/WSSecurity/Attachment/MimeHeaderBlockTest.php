<?php
declare(strict_types=1);

namespace SoapTest\Psr18WsseMiddleware\Unit\WSSecurity\Attachment;

use PHPUnit\Framework\TestCase;
use Psl\MIME\Headers;
use Soap\Psr18WsseMiddleware\WSSecurity\Attachment\MimeHeaderBlock;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\MalformedAttachmentHeaders;
use Soap\Psr18WsseMiddleware\WSSecurity\Exception\UnsupportedAttachmentHeaderForm;

final class MimeHeaderBlockTest extends TestCase
{
    public function test_it_canonicalizes_the_header_set_this_package_emits(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Disposition:attachment;filename=\"invoice.pdf\";name=\"invoice\"\r\n"
            ."Content-ID:<invoice@example.com>\r\n"
            ."Content-Type:application/pdf\r\n",
            $block->canonicalize(Headers::fromPairs([
                ['Content-ID', '<invoice@example.com>'],
                ['Content-Type', 'application/pdf'],
                ['Content-Disposition', 'attachment; name="invoice"; filename="invoice.pdf"'],
            ]))
        );
    }

    public function test_it_considers_only_the_five_profile_headers(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Type:application/pdf\r\n",
            $block->canonicalize(Headers::fromPairs([
                ['Content-Type', 'application/pdf'],
                ['Content-Transfer-Encoding', 'binary'],
                ['X-Whatever', 'ignored'],
            ]))
        );
    }

    public function test_it_matches_header_names_case_insensitively_and_emits_the_profile_casing(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-ID:<invoice@example.com>\r\n"
            ."Content-Type:application/pdf\r\n",
            $block->canonicalize(Headers::fromPairs([
                ['CONTENT-TYPE', 'application/pdf'],
                ['content-id', '<invoice@example.com>'],
            ]))
        );
    }

    public function test_it_substitutes_an_absent_content_type(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-ID:<invoice@example.com>\r\n"
            ."Content-Type:text/plain;charset=\"us-ascii\"\r\n",
            $block->canonicalize(Headers::fromPairs([['Content-ID', '<invoice@example.com>']]))
        );
    }

    public function test_it_emits_the_headers_it_covers_in_ascending_name_order(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Disposition:attachment\r\n"
            ."Content-ID:<invoice@example.com>\r\n"
            ."Content-Location:http://example.com/invoice.pdf\r\n"
            ."Content-Type:application/pdf\r\n",
            $block->canonicalize(Headers::fromPairs([
                ['Content-Type', 'application/pdf'],
                ['Content-Location', 'http://example.com/invoice.pdf'],
                ['Content-ID', '<invoice@example.com>'],
                ['Content-Disposition', 'attachment'],
            ]))
        );
    }

    public function test_it_strips_leading_whitespace_from_a_value(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-ID:<invoice@example.com>\r\n"
            ."Content-Type:text/plain;charset=\"us-ascii\"\r\n",
            $block->canonicalize(Headers::fromPairs([['Content-ID', "\t <invoice@example.com>"]]))
        );
    }

    public function test_it_lowercases_the_essence_and_the_parameter_names_of_a_parameterized_value(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Type:text/plain;charset=\"utf-8\"\r\n",
            $block->canonicalize(Headers::fromPairs([['Content-Type', 'TEXT/Plain; CharSet=UTF-8']]))
        );
    }

    public function test_it_leaves_a_value_without_parameters_alone(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Type:TEXT/Plain\r\n",
            $block->canonicalize(Headers::fromPairs([['Content-Type', 'TEXT/Plain']]))
        );
    }

    public function test_it_sorts_parameters_and_quotes_their_values(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Type:application/pdf;name=\"Invoice\";zoom=\"3\"\r\n",
            $block->canonicalize(Headers::fromPairs([
                ['Content-Type', 'application/pdf; zoom=3; name=Invoice'],
            ]))
        );
    }

    public function test_it_lowercases_the_values_of_the_parameters_the_profile_names(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Disposition:attachment;filename=\"invoice.pdf\";name=\"Invoice\"\r\n"
            ."Content-Type:text/plain;charset=\"us-ascii\"\r\n",
            $block->canonicalize(Headers::fromPairs([
                ['Content-Disposition', 'attachment; filename="Invoice.PDF"; name="Invoice"'],
            ]))
        );
    }

    public function test_it_refuses_a_header_set_carrying_a_duplicate_profile_header(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Type" appears 2 times');

        $block->canonicalize(Headers::fromPairs([
            ['Content-Type', 'application/pdf'],
            ['content-type', 'text/plain'],
        ]));
    }

    public function test_it_ignores_a_duplicate_of_a_header_it_does_not_consider(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Type:application/pdf\r\n",
            $block->canonicalize(Headers::fromPairs([
                ['Content-Type', 'application/pdf'],
                ['Content-Transfer-Encoding', 'binary'],
                ['Content-Transfer-Encoding', '8bit'],
            ]))
        );
    }

    public function test_it_refuses_a_content_description(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Description" is the one header');

        $block->canonicalize(Headers::fromPairs([
            ['Content-Type', 'application/pdf'],
            ['Content-Description', 'an invoice'],
        ]));
    }

    public function test_it_refuses_a_header_carrying_a_comment(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Type" carries a comment');

        $block->canonicalize(Headers::fromPairs([['Content-Type', 'application/pdf (the invoice)']]));
    }

    public function test_it_accepts_a_parenthesis_inside_a_quoted_string(): void
    {
        $block = new MimeHeaderBlock();

        static::assertSame(
            "Content-Type:application/pdf;name=\"a (b)\"\r\n",
            $block->canonicalize(Headers::fromPairs([['Content-Type', 'application/pdf; name="a (b)"']]))
        );
    }

    public function test_it_refuses_a_parameter_continuation(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Disposition" carries a continued or charset-tagged parameter');

        $block->canonicalize(Headers::fromPairs([
            ['Content-Disposition', 'attachment; filename*0="in"; filename*1="voice.pdf"'],
        ]));
    }

    public function test_it_refuses_a_charset_tagged_parameter(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Type" carries a continued or charset-tagged parameter');

        $block->canonicalize(Headers::fromPairs([
            ['Content-Type', "application/pdf; name*=utf-8''facture.pdf"],
        ]));
    }

    public function test_it_refuses_a_parameter_without_a_value(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(UnsupportedAttachmentHeaderForm::class);
        $this->expectExceptionMessage('"Content-Type" carries a parameter this cannot read');

        $block->canonicalize(Headers::fromPairs([['Content-Type', 'application/pdf; broken']]));
    }

    public function test_it_decodes_a_header_block_and_the_bytes_after_it(): void
    {
        $block = new MimeHeaderBlock();

        $decoded = $block->decode(
            "Content-ID: <invoice@example.com>\r\n"
            ."Content-Type: application/pdf\r\n"
            ."\r\n"
            ."the bytes\r\nand more"
        );

        static::assertSame(
            [
                ['Content-ID', '<invoice@example.com>'],
                ['Content-Type', 'application/pdf'],
            ],
            $decoded->headers->pairs()
        );
        static::assertSame("the bytes\r\nand more", $decoded->content);
    }

    public function test_it_decodes_an_empty_header_block(): void
    {
        $block = new MimeHeaderBlock();

        $decoded = $block->decode("\r\nthe bytes");

        static::assertCount(0, $decoded->headers);
        static::assertSame('the bytes', $decoded->content);
    }

    public function test_it_decodes_a_part_with_no_bytes_after_the_blank_line(): void
    {
        $block = new MimeHeaderBlock();

        $decoded = $block->decode("Content-ID: <invoice@example.com>\r\n\r\n");

        static::assertSame('', $decoded->content);
    }

    public function test_it_refuses_octets_without_a_blank_line(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(MalformedAttachmentHeaders::class);
        $this->expectExceptionMessage('no blank line');

        $block->decode("Content-ID: <invoice@example.com>\r\nthe bytes");
    }

    public function test_it_refuses_a_header_line_without_a_colon(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(MalformedAttachmentHeaders::class);
        $this->expectExceptionMessage('carries no colon');

        $block->decode("this is not a header\r\n\r\nthe bytes");
    }

    public function test_it_refuses_a_header_name_a_mime_header_cannot_carry(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(MalformedAttachmentHeaders::class);
        $this->expectExceptionMessage('carries a header that is not a valid MIME header');

        $block->decode("Content-Location: http://example.com/a\r\n http://example.com/b\r\n\r\nthe bytes");
    }

    public function test_it_refuses_a_header_value_a_mime_header_cannot_carry(): void
    {
        $block = new MimeHeaderBlock();

        $this->expectException(MalformedAttachmentHeaders::class);
        $this->expectExceptionMessage('carries a header that is not a valid MIME header');

        $block->decode("Content-ID: <invoice\0@example.com>\r\n\r\nthe bytes");
    }

    public function test_it_refuses_more_header_lines_than_the_cap_allows(): void
    {
        $block = new MimeHeaderBlock();

        $octets = str_repeat("X-Filler: value\r\n", MimeHeaderBlock::MAX_HEADERS + 1)."\r\nthe bytes";

        $this->expectException(MalformedAttachmentHeaders::class);
        $this->expectExceptionMessage('more than 100 headers');

        $block->decode($octets);
    }

    public function test_it_refuses_a_header_line_longer_than_the_cap_allows(): void
    {
        $block = new MimeHeaderBlock();

        $octets = 'X-Filler: '.str_repeat('a', MimeHeaderBlock::MAX_LINE_LENGTH)."\r\n\r\nthe bytes";

        $this->expectException(MalformedAttachmentHeaders::class);
        $this->expectExceptionMessage('longer than 1000 characters');

        $block->decode($octets);
    }

    public function test_it_stops_scanning_for_the_blank_line_at_the_line_cap(): void
    {
        $block = new MimeHeaderBlock();

        $octets = str_repeat('a', 4096);

        $this->expectException(MalformedAttachmentHeaders::class);

        $block->decode($octets);
    }
}
