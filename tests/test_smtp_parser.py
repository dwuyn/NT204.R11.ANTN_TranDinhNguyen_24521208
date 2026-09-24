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


if __name__ == "__main__":
    unittest.main()
