import unittest
from leak_data_parser.parser import parse_line


class TestParser(unittest.TestCase):
    def test_email_password(self):
        line = "user@example.com:pass123"
        self.assertEqual(
            parse_line(line), {"email": "user@example.com", "password": "pass123"}
        )

    def test_email_password_url(self):
        line = "user@example.com:pass123:http://site.com"
        expected = {
            "email": "user@example.com",
            "password": "pass123",
            "url": "http://site.com",
        }
        self.assertEqual(parse_line(line), expected)

    def test_ip_username_password(self):
        line = "192.168.0.1:admin:secret"
        self.assertEqual(
            parse_line(line),
            {"ip": "192.168.0.1", "username": "admin", "password": "secret"},
        )

    def test_url_username_password(self):
        line = "http://example.com | user71@example.com:user72"
        expected = {
            "email": "user71@example.com",
            "password": "user72",
            "url": "http://example.com",
        }
        self.assertEqual(parse_line(line), expected)

    def test_ip_email_password(self):
        line = "10.0.0.1:user@example.com:pwd"
        self.assertEqual(
            parse_line(line),
            {"ip": "10.0.0.1", "email": "user@example.com", "password": "pwd"},
        )

    def test_invalid_missing_password(self):
        self.assertIsNone(parse_line("user@example.com"))

    def test_invalid_username_password(self):
        self.assertIsNone(parse_line("user:pass"))

    def test_malformed_email(self):
        self.assertIsNone(parse_line("user@@example.com:pass"))

    def test_extra_separators(self):
        line = "user@example.com;;:pass"
        self.assertEqual(
            parse_line(line), {"email": "user@example.com", "password": "pass"}
        )


if __name__ == "__main__":
    unittest.main()
