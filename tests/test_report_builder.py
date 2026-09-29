import unittest

from src.gui.report_builder import build_report_html
from src.gui.theme import LIGHT_PALETTE
from src.usecases.analyze_mail import analyze_mail_text


class ReportBuilderTests(unittest.TestCase):
    RAW_MAIL = (
        "From: sender@example.com\n"
        "X-Spam-Level: ****\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "https://example.com/path"
    )

    def test_report_respects_enabled_url_defanging(self):
        result = analyze_mail_text(self.RAW_MAIL, defang_urls=True)

        report = build_report_html(result, LIGHT_PALETTE)

        self.assertIn("hxxps://example[.]com/path", report)

    def test_report_respects_disabled_url_defanging(self):
        result = analyze_mail_text(self.RAW_MAIL, defang_urls=False)

        report = build_report_html(result, LIGHT_PALETTE)

        self.assertIn("https://example.com/path", report)
        self.assertNotIn("hxxps://example[.]com/path", report)

    def test_unknown_spam_status_is_not_shown_as_safe(self):
        result = analyze_mail_text(self.RAW_MAIL)

        report = build_report_html(result, LIGHT_PALETTE)

        self.assertIn("不明", report)
        self.assertIn(f'color:{LIGHT_PALETTE["warn"]}', report)


if __name__ == "__main__":
    unittest.main()
