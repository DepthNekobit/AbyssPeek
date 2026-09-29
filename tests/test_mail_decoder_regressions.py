import unittest

from src.services.mail_decoder import decode_mail_text


class MailDecoderRegressionTests(unittest.TestCase):
    def test_utf8_bom_is_ignored(self):
        decoded = decode_mail_text("\ufeffFrom: sender@example.com\nSubject: test\n\nbody")

        self.assertEqual(decoded.first_header("From"), "sender@example.com")
        self.assertEqual(decoded.first_header("Subject"), "test")
        self.assertEqual(decoded.body_text, "body")

    def test_unicode_text_is_not_redecoded_using_declared_charset(self):
        decoded = decode_mail_text("Content-Type: text/plain; charset=iso-8859-1\n\ncafé")

        self.assertEqual(decoded.body_text, "café")

    def test_unicode_japanese_text_is_preserved(self):
        decoded = decode_mail_text("Content-Type: text/plain; charset=cp932\n\n日本")

        self.assertEqual(decoded.body_text, "日本")

    def test_base64_text_still_decodes(self):
        decoded = decode_mail_text(
            "Content-Type: text/plain; charset=utf-8\n"
            "Content-Transfer-Encoding: base64\n\n5pel5pys"
        )

        self.assertEqual(decoded.body_text, "日本")

    def test_inline_text_attachment_is_not_selected_as_body(self):
        decoded = decode_mail_text(
            "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n\n"
            "--x\nContent-Type: text/html; charset=utf-8\n\n"
            "<html><body>REAL HTML BODY</body></html>\n"
            "--x\nContent-Type: text/plain; name=notes.txt\n"
            "Content-Disposition: inline; filename=notes.txt\n\n"
            "ATTACHMENT TEXT\n--x--\n"
        )

        self.assertEqual(decoded.body_text, "REAL HTML BODY")
        self.assertEqual([item.filename for item in decoded.attachments], ["notes.txt"])

    def test_attached_message_body_is_not_selected_as_outer_body(self):
        decoded = decode_mail_text(
            "MIME-Version: 1.0\n"
            "Content-Type: multipart/mixed; boundary=outer\n\n"
            "--outer\n"
            "Content-Type: message/rfc822\n"
            'Content-Disposition: attachment; filename="forwarded.eml"\n\n'
            "From: attached@example.com\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "attached message body\n"
            "--outer\n"
            "Content-Type: text/plain; charset=utf-8\n\n"
            "actual outer body\n"
            "--outer--\n"
        )

        self.assertEqual(decoded.body_text, "actual outer body")


if __name__ == "__main__":
    unittest.main()
