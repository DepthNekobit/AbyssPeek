import unittest

from src.services.security_analyzer import defang_text, defang_url


class DefangRegressionTests(unittest.TestCase):
    def test_bare_domain_is_defanged(self):
        self.assertEqual(defang_text("Visit evil.com/login"), "Visit evil[.]com/login")

    def test_email_address_is_not_treated_as_bare_url(self):
        self.assertEqual(defang_text("Contact user@example.com"), "Contact user@example.com")

    def test_uppercase_host_and_userinfo_defang_the_actual_host(self):
        self.assertEqual(
            defang_url("HTTPS://EXAMPLE.COM@EXAMPLE.COM/path"),
            "hxxps://EXAMPLE.COM@EXAMPLE[.]COM/path",
        )


if __name__ == "__main__":
    unittest.main()
