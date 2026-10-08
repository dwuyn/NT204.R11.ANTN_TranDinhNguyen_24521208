"""Unit tests for parsers/application/smtp.py."""

import unittest

from parsers.application.smtp import SmtpParser


class TestSmtpParser(unittest.TestCase):
    def test_smtp_command_helo(self):
        payload = b"HELO mail.client.org\r\n"
        app, errors = SmtpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(errors, [])
        self.assertEqual(app.protocol, "SMTP")
        self.assertEqual(app.type, "command")
        self.assertEqual(app.details["command"], "HELO")
        self.assertEqual(app.details["argument"], "mail.client.org")

    def test_smtp_command_mail_from(self):
        payload = b"MAIL FROM:<sender@domain.com>\r\n"
        app, errors = SmtpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(app.type, "command")
        self.assertEqual(app.details["command"], "MAIL FROM")
        self.assertEqual(app.details["argument"], "<sender@domain.com>")

    def test_smtp_command_rcpt_to(self):
        payload = b"RCPT TO: <recipient@domain.com>\r\n"
        app, errors = SmtpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(app.type, "command")
        self.assertEqual(app.details["command"], "RCPT TO")
        self.assertEqual(app.details["argument"], "<recipient@domain.com>")

    def test_smtp_response_greeting_220(self):
        payload = b"220 mail.domain.com ESMTP Postfix Service Ready\r\n"
        app, errors = SmtpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(app.protocol, "SMTP")
        self.assertEqual(app.type, "response")
        self.assertEqual(app.details["status_code"], 220)
        self.assertIn("Service Ready", app.details["message"])

    def test_smtp_response_250_multiline(self):
        payload = b"250-mail.domain.com\r\n250-PIPELINING\r\n250 8BITMIME\r\n"
        app, errors = SmtpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(app.type, "response")
        self.assertEqual(app.details["status_code"], 250)
        self.assertEqual(len(app.details["raw_lines"]), 3)

    def test_smtp_response_error_550(self):
        payload = b"550 5.1.1 <nobody@domain.com>: Recipient address rejected\r\n"
        app, errors = SmtpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(app.details["status_code"], 550)

    def test_smtp_malformed(self):
        payload = b"RANDOM_INVALID_DATA_NOT_SMTP\r\n"
        app, errors = SmtpParser.parse(payload)

        self.assertIsNone(app)
        self.assertTrue(len(errors) > 0)


class TestSmtpMimeParsing(unittest.TestCase):
    def test_mime_message_is_parsed_as_data(self):
        payload = (
            b"From: sender@uit.edu.vn\r\n"
            b"To: rcpt@uit.edu.vn\r\n"
            b"Subject: =?utf-8?B?VMOhaSBraG9hbg==?=\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgbWVzc2FnZS4="
        )
        app, errors = SmtpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(errors, [])
        self.assertEqual(app.protocol, "SMTP")
        self.assertEqual(app.type, "data")
        self.assertTrue(app.details["mime"])
        self.assertEqual(
            app.details["headers"]["Content-Transfer-Encoding"], "base64"
        )
        self.assertEqual(
            app.details["body"], "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgbWVzc2FnZS4="
        )

    def test_mime_message_without_mime_version(self):
        payload = (
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"H=E1=BB=87 th=E1=BB=91ng IDS"
        )
        app, errors = SmtpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(app.type, "data")
        self.assertEqual(app.details["headers"]["Content-Transfer-Encoding"], "quoted-printable")

    def test_duplicate_header_keeps_first_value(self):
        payload = (
            b"Subject: first\r\n"
            b"Subject: second\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            b"body"
        )
        app, _errors = SmtpParser.parse(payload)

        self.assertEqual(app.details["headers"]["Subject"], "first")

    def test_commands_and_responses_still_take_priority(self):
        app, _errors = SmtpParser.parse(b"MAIL FROM:<a@b.c>\r\n")
        self.assertEqual(app.type, "command")

        app, _errors = SmtpParser.parse(b"250 OK\r\n")
        self.assertEqual(app.type, "response")

    def test_malformed_payload_is_still_unrecognized(self):
        app, errors = SmtpParser.parse(b"RANDOM_INVALID_DATA_NOT_SMTP\r\n")
        self.assertIsNone(app)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
