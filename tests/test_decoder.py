"""Unit tests for the decoder stage (percent, form, HTML entity, character decoding)."""

import unittest

from config import DecoderConfig
from decoder.decoder import Decoder
from parsers.models import ApplicationLayer, NormalizedEvent


def _event(payload: bytes, application) -> NormalizedEvent:
    event = NormalizedEvent(packet_id=1, timestamp=1700000000.0, raw_len=len(payload))
    event.application = application
    return event


def _request(payload: bytes, uri: str, headers=None) -> ApplicationLayer:
    return ApplicationLayer(
        protocol="HTTP",
        type="request",
        details={
            "method": "GET",
            "uri": uri,
            "version": "HTTP/1.1",
            "headers": dict(headers or {}),
            "body": "",
        },
    )


def _response(payload: bytes, headers=None, body: bytes = b"") -> ApplicationLayer:
    return ApplicationLayer(
        protocol="HTTP",
        type="response",
        details={
            "version": "HTTP/1.1",
            "status_code": 200,
            "reason": "OK",
            "headers": dict(headers or {}),
            "body": body.decode("latin-1"),
        },
    )


class TestHttpDecoder(unittest.TestCase):
    def setUp(self):
        self.decoder = Decoder(DecoderConfig())

    def _decode(self, payload: bytes, application):
        event = _event(payload, application)
        self.decoder.decode(event, payload)
        return event

    # ------------------------------------------------------------------
    # Percent / URL decoding
    # ------------------------------------------------------------------

    def test_percent_decoding_in_request_uri(self):
        uri = "/search?q=%27%20OR%201%3D1&lang=en"
        payload = f"GET {uri} HTTP/1.1\r\nHost: ids.local\r\n\r\n".encode()
        event = self._decode(payload, _request(payload, uri))

        self.assertEqual(event.decode.decode_status, "decoded")
        self.assertEqual(event.decode.decoders, ["percent_url"])
        self.assertEqual(event.decode.fields["uri_decoded"], "/search?q=' OR 1=1&lang=en")
        # The raw, still-encoded URI must be preserved for reference.
        self.assertEqual(event.application.details["uri"], uri)

    def test_uri_without_percent_escape_adds_no_decoder(self):
        uri = "/api/v1/network/stats"
        payload = f"GET {uri} HTTP/1.1\r\nHost: ids.local\r\n\r\n".encode()
        event = self._decode(payload, _request(payload, uri))

        self.assertEqual(event.decode.fields["uri_decoded"], uri)
        self.assertEqual(event.decode.decoders, [])
        self.assertEqual(event.decode.decode_status, "unchanged")

    def test_response_is_not_uri_decoded(self):
        body = b"OK"
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body
        event = self._decode(payload, _response(payload, {"Content-Type": "text/plain"}, body))

        self.assertNotIn("uri_decoded", event.decode.fields)
        self.assertEqual(event.decode.fields["body_decoded"], "OK")

    # ------------------------------------------------------------------
    # HTML entities
    # ------------------------------------------------------------------

    def test_html_entity_decoding_in_text_body(self):
        body = b"<p>Hello &lt;script&gt;alert(1)&lt;/script&gt; &amp; welcome</p>"
        headers = {"Content-Type": "text/html; charset=utf-8"}
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n" + body
        event = self._decode(payload, _response(payload, headers, body))

        self.assertEqual(
            event.decode.fields["body_decoded"],
            "<p>Hello <script>alert(1)</script> & welcome</p>",
        )
        self.assertEqual(event.decode.fields["body_charset"], "utf-8")
        self.assertEqual(event.decode.fields["body_decode_status"], "ok")
        self.assertIn("html_entities", event.decode.decoders)
        self.assertEqual(event.decode.decode_status, "decoded")
        # Raw body stays untouched.
        self.assertEqual(event.application.details["body"], body.decode("latin-1"))

    def test_html_entities_can_be_disabled(self):
        decoder = Decoder(DecoderConfig(decode_html_entities=False))
        body = b"a &amp; b"
        headers = {"Content-Type": "text/plain"}
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" + body
        event = _event(payload, _response(payload, headers, body))
        decoder.decode(event, payload)

        self.assertEqual(event.decode.fields["body_decoded"], "a &amp; b")
        self.assertNotIn("html_entities", event.decode.decoders)

    # ------------------------------------------------------------------
    # Form bodies
    # ------------------------------------------------------------------

    def test_form_body_decoding(self):
        body = b"username=admin&password=a%20b"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = (
            b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body
        )
        event = self._decode(payload, _request(payload, "/login", headers))

        self.assertEqual(event.decode.fields["form_fields"], {"username": "admin", "password": "a b"})
        self.assertEqual(event.decode.fields["body_decoded"], "username=admin&password=a b")
        self.assertEqual(event.decode.fields["body_decode_status"], "ok")
        self.assertIn("form_urlencoded", event.decode.decoders)

    def test_form_plus_sign_becomes_space(self):
        body = b"q=a+b&x=1"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = b"POST /s HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body
        event = self._decode(payload, _request(payload, "/s", headers))

        self.assertEqual(event.decode.fields["form_fields"]["q"], "a b")

    def test_duplicate_form_key_keeps_first_and_warns(self):
        body = b"a=1&a=2"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = b"POST /s HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body
        event = self._decode(payload, _request(payload, "/s", headers))

        self.assertEqual(event.decode.fields["form_fields"], {"a": "1"})
        self.assertIn("duplicate_form_field", event.decode.warnings)

    def test_form_decoding_can_be_disabled(self):
        decoder = Decoder(DecoderConfig(decode_form_urlencoded=False))
        body = b"a=1"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        payload = b"POST /s HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body
        event = _event(payload, _request(payload, "/s", headers))
        decoder.decode(event, payload)

        self.assertNotIn("form_fields", event.decode.fields)
        self.assertNotIn("form_urlencoded", event.decode.decoders)

    # ------------------------------------------------------------------
    # Character decoding / robustness
    # ------------------------------------------------------------------

    def test_invalid_utf8_body_is_partial_not_error(self):
        body = b"\xff\xfe abc"
        headers = {"Content-Type": "text/plain"}
        payload = b"POST /u HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n" + body
        event = self._decode(payload, _request(payload, "/u", headers))

        self.assertEqual(event.decode.decode_status, "partial")
        self.assertIn("invalid_utf8_sequence", event.decode.warnings)
        self.assertEqual(event.decode.fields["body_decode_status"], "partial")
        self.assertNotEqual(event.decode.decode_status, "error")

    def test_binary_body_is_skipped_with_warning(self):
        body = b"\x89PNG\r\n\x1a\n\x00\x00"
        headers = {"Content-Type": "image/png"}
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n" + body
        event = self._decode(payload, _response(payload, headers, body))

        self.assertEqual(event.decode.fields["body_decode_status"], "skipped")
        self.assertIn("binary_body_not_decoded", event.decode.warnings)
        self.assertNotIn("body_decoded", event.decode.fields)

    def test_payload_larger_than_limit_is_skipped(self):
        decoder = Decoder(DecoderConfig(max_decode_size=16))
        payload = b"GET /abc HTTP/1.1\r\nHost: ids.local\r\n\r\n" + b"x" * 32
        event = _event(payload, _request(payload, "/abc"))
        decoder.decode(event, payload)

        self.assertEqual(event.decode.decode_status, "skipped")
        self.assertIn("payload_too_large", event.decode.warnings)
        self.assertEqual(event.decode.fields, {})
        self.assertEqual(event.decode.decoders, [])

    def test_unknown_protocol_binary_payload_is_partial(self):
        payload = b"\x99\x88\x77\x66\x55\x44custom protocol data"
        app = ApplicationLayer(protocol="UNKNOWN", type="default", details={})
        event = self._decode(payload, app)

        self.assertEqual(event.decode.decode_status, "partial")
        self.assertIn("invalid_utf8_sequence", event.decode.warnings)

    def test_dns_payload_stays_unchanged(self):
        payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06portal\x03uit\x03edu\x02vn"
        app = ApplicationLayer(protocol="DNS", type="query", details={"id": 0x1234})
        event = self._decode(payload, app)

        self.assertEqual(event.decode.decode_status, "unchanged")
        self.assertEqual(event.decode.warnings, [])
        self.assertEqual(event.decode.fields, {})

    def test_missing_content_type_accepts_utf8_text(self):
        body = b"plain text body"
        payload = b"HTTP/1.1 200 OK\r\n\r\n" + body
        event = self._decode(payload, _response(payload, {}, body))

        self.assertEqual(event.decode.fields["body_decoded"], "plain text body")
        self.assertEqual(event.decode.fields["body_decode_status"], "ok")

    def test_missing_content_type_binary_body_is_skipped(self):
        body = b"\xff\xfe\x00binary"
        payload = b"HTTP/1.1 200 OK\r\n\r\n" + body
        event = self._decode(payload, _response(payload, {}, body))

        self.assertEqual(event.decode.fields["body_decode_status"], "skipped")
        self.assertNotIn("body_decoded", event.decode.fields)
        self.assertEqual(event.decode.decode_status, "partial")  # payload level check

    def test_unknown_charset_warns_and_falls_back_to_utf8(self):
        body = b"hello"
        headers = {"Content-Type": "text/plain; charset=koi8-r"}
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=koi8-r\r\n\r\n" + body
        event = self._decode(payload, _response(payload, headers, body))

        self.assertIn("unknown_charset", event.decode.warnings)
        self.assertEqual(event.decode.fields["body_charset"], "utf-8")
        self.assertEqual(event.decode.fields["body_decoded"], "hello")

    def test_latin1_charset_accepts_high_bytes(self):
        body = b"caf\xe9"
        headers = {"Content-Type": "text/plain; charset=iso-8859-1"}
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\n" + body
        event = self._decode(payload, _response(payload, headers, body))

        # The body decodes cleanly through its declared charset...
        self.assertEqual(event.decode.fields["body_decoded"], "café")
        self.assertEqual(event.decode.fields["body_charset"], "latin-1")
        self.assertEqual(event.decode.fields["body_decode_status"], "ok")
        # ...but the raw wire bytes are not valid UTF-8, so the payload-level
        # character check still reports the event as partially decoded.
        self.assertEqual(event.decode.decode_status, "partial")
        self.assertIn("invalid_utf8_sequence", event.decode.warnings)

    def test_empty_payload_is_unchanged(self):
        payload = b""
        app = ApplicationLayer(protocol="HTTP", type="request", details={"uri": "/"})
        event = self._decode(payload, app)

        self.assertEqual(event.decode.decode_status, "unchanged")
        self.assertEqual(event.decode.decoders, [])
        self.assertEqual(event.decode.fields, {"uri_decoded": "/"})

    def test_no_application_layer_is_unchanged(self):
        event = _event(b"", None)
        self.decoder.decode(event, b"")
        self.assertIsNotNone(event.decode)
        self.assertEqual(event.decode.decode_status, "unchanged")

    def test_decode_never_raises_on_hostile_input(self):
        hostile_apps = [
            ApplicationLayer(protocol="HTTP", type="request", details=[]),
            ApplicationLayer(protocol="HTTP", type="request", details={"uri": b"/bytes"}),
            ApplicationLayer(protocol="HTTP", type="response", details={"headers": "nope"}),
            ApplicationLayer(protocol="HTTP", type="request", details={"headers": {"Content-Type": 5}}),
            ApplicationLayer(protocol="SMTP", type="data", details=None),
        ]
        for app in hostile_apps:
            for payload in (b"", b"\xff\xfe", b"GET / HTTP/1.1\r\n\r\n\xff"):
                event = _event(payload, app)
                self.decoder.decode(event, payload)
                self.assertIn(
                    event.decode.decode_status,
                    {"unchanged", "skipped", "decoded", "partial", "error"},
                )


class TestMimeDecoder(unittest.TestCase):
    BASE64_MESSAGE = (
        b"From: sender@uit.edu.vn\r\n"
        b"To: rcpt@uit.edu.vn\r\n"
        b"Subject: =?utf-8?B?VMOhaSBraG9hbg==?=\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgbWVzc2FnZS4="
    )

    QUOTED_PRINTABLE_MESSAGE = (
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n"
        b"\r\n"
        b"H=E1=BB=87 th=E1=BB=91ng IDS =C4=91ang ho=E1=BA=A1t =C4=91=E1=BB=99ng."
    )

    def setUp(self):
        self.decoder = Decoder(DecoderConfig())

    def _decode(self, payload: bytes):
        app = ApplicationLayer(protocol="SMTP", type="data", details={"mime": True})
        event = _event(payload, app)
        self.decoder.decode(event, payload)
        return event

    def test_base64_body_is_decoded(self):
        event = self._decode(self.BASE64_MESSAGE)

        self.assertEqual(
            event.decode.fields["mime_body_decoded"], "Hello World! This is a base64 message."
        )
        self.assertEqual(event.decode.fields["content_transfer_encoding"], "base64")
        self.assertEqual(event.decode.fields["mime_charset"], "utf-8")
        self.assertIn("base64", event.decode.decoders)
        self.assertEqual(event.decode.decode_status, "decoded")

    def test_rfc2047_subject_header_is_decoded(self):
        event = self._decode(self.BASE64_MESSAGE)

        self.assertEqual(event.decode.fields["headers_decoded"]["Subject"], "Tái khoan")
        self.assertIn("rfc2047", event.decode.decoders)

    def test_quoted_printable_body_is_decoded(self):
        event = self._decode(self.QUOTED_PRINTABLE_MESSAGE)

        self.assertEqual(event.decode.fields["mime_body_decoded"], "Hệ thống IDS đang hoạt động.")
        self.assertEqual(event.decode.fields["content_transfer_encoding"], "quoted-printable")
        self.assertIn("quoted_printable", event.decode.decoders)

    def test_broken_base64_stays_partial_without_raising(self):
        payload = (
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"!!!not-base64!!!"
        )
        event = self._decode(payload)

        self.assertEqual(event.decode.decode_status, "partial")
        self.assertIn("base64_decode_error", event.decode.warnings)
        self.assertNotIn("base64", event.decode.decoders)

    def test_8bit_body_with_invalid_utf8_is_partial(self):
        payload = b"Content-Transfer-Encoding: 8bit\r\n\r\n" + b"\xff\xfe"
        event = self._decode(payload)

        self.assertEqual(event.decode.decode_status, "partial")
        self.assertIn("invalid_utf8_sequence", event.decode.warnings)

    def test_7bit_plain_body_is_used_as_is(self):
        payload = b"Content-Transfer-Encoding: 7bit\r\n\r\nplain ascii body"
        event = self._decode(payload)

        self.assertEqual(event.decode.fields["mime_body_decoded"], "plain ascii body")
        self.assertEqual(event.decode.decoders, [])
        self.assertEqual(event.decode.decode_status, "unchanged")

    def test_html_mime_body_gets_entity_decoding(self):
        payload = (
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: 7bit\r\n"
            b"\r\n"
            b"<b>a &amp; b</b>"
        )
        event = self._decode(payload)

        self.assertEqual(event.decode.fields["mime_body_decoded"], "<b>a & b</b>")
        self.assertIn("html_entities", event.decode.decoders)

    def test_mime_decoding_can_be_disabled(self):
        decoder = Decoder(DecoderConfig(decode_mime=False))
        app = ApplicationLayer(protocol="SMTP", type="data", details={"mime": True})
        event = _event(self.BASE64_MESSAGE, app)
        decoder.decode(event, self.BASE64_MESSAGE)

        self.assertEqual(event.decode.decode_status, "unchanged")
        self.assertEqual(event.decode.fields, {})
        self.assertEqual(event.decode.decoders, [])

    def test_smtp_command_payload_is_not_mime_decoded(self):
        payload = b"MAIL FROM:<sender@uit.edu.vn>\r\n"
        app = ApplicationLayer(protocol="SMTP", type="command", details={"command": "MAIL FROM"})
        event = _event(payload, app)
        self.decoder.decode(event, payload)

        self.assertEqual(event.decode.decode_status, "unchanged")
        self.assertNotIn("mime_body_decoded", event.decode.fields)


if __name__ == "__main__":
    unittest.main()
