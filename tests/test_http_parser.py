"""Unit tests for parsers/application/http.py."""

import unittest

from parsers.application.http import HttpParser


class TestHttpParser(unittest.TestCase):
    def test_http_get_request(self):
        payload = b"GET /index.html?user=alice HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\n\r\n"
        app, errors = HttpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(errors, [])
        self.assertEqual(app.protocol, "HTTP")
        self.assertEqual(app.type, "request")
        self.assertEqual(app.details["method"], "GET")
        self.assertEqual(app.details["uri"], "/index.html?user=alice")
        self.assertEqual(app.details["version"], "HTTP/1.1")
        self.assertEqual(app.details["headers"]["Host"], "example.com")
        self.assertEqual(app.details["headers"]["User-Agent"], "curl/7.68.0")
        self.assertEqual(app.details["body"], "")

    def test_http_post_request_with_body(self):
        body = '{"username": "admin", "password": "secret"}'
        payload = (
            f"POST /api/v1/auth HTTP/1.1\r\n"
            f"Host: api.local\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
            f"{body}"
        ).encode("utf-8")

        app, errors = HttpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(app.type, "request")
        self.assertEqual(app.details["method"], "POST")
        self.assertEqual(app.details["uri"], "/api/v1/auth")
        self.assertEqual(app.details["headers"]["Content-Type"], "application/json")
        self.assertEqual(app.details["body"], body)

    def test_http_response(self):
        body = "<html><body>Welcome</body></html>"
        payload = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: nginx/1.18.0\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n\r\n"
            f"{body}"
        ).encode("utf-8")

        app, errors = HttpParser.parse(payload)

        self.assertIsNotNone(app)
        self.assertEqual(app.type, "response")
        self.assertEqual(app.details["version"], "HTTP/1.1")
        self.assertEqual(app.details["status_code"], 200)
        self.assertEqual(app.details["reason"], "OK")
        self.assertEqual(app.details["headers"]["Server"], "nginx/1.18.0")
        self.assertEqual(app.details["body"], body)

    def test_http_malformed(self):
        payload = b"GARBAGE_WITHOUT_SPACES\r\nHeader: Value\r\n\r\n"
        app, errors = HttpParser.parse(payload)
        self.assertIsNone(app)
        self.assertTrue(len(errors) > 0)


if __name__ == "__main__":
    unittest.main()
