import unittest

from src.usecases.analyze_mail import analyze_mail_text


class SecurityRegressionTests(unittest.TestCase):
    @staticmethod
    def _auth_message(authserv_id: str) -> str:
        return (
            f"Authentication-Results: {authserv_id}; spf=pass smtp.mailfrom=paypal.com; "
            "dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com\n"
            "Received: from attacker.example [8.8.8.8] by mx.victim.example; "
            "Tue, 14 Jul 2026 12:00:00 +0900\n"
            "From: PayPal <billing@paypal.com>\n"
            "Message-ID: <test@attacker.example>\n"
            "Subject: Your receipt\n\nHello"
        )

    def test_untrusted_authentication_results_do_not_establish_auth(self):
        result = analyze_mail_text(self._auth_message("attacker.example"))

        self.assertIsNone(result.security.auth.spf)
        self.assertIsNone(result.security.auth.dkim)
        self.assertIsNone(result.security.auth.dmarc)
        self.assertNotEqual(result.security.risk_level, "問題なし")

    def test_authentication_results_from_receiving_server_remain_valid(self):
        result = analyze_mail_text(self._auth_message("mx.victim.example"))

        self.assertEqual(result.security.auth.spf, "pass")
        self.assertEqual(result.security.auth.dkim, "pass")
        self.assertEqual(result.security.auth.dmarc, "pass")

    def test_dmarc_pass_for_another_from_domain_is_not_trusted(self):
        result = analyze_mail_text(
            "Authentication-Results: mx.victim.example; spf=fail smtp.mailfrom=evil.example; "
            "dkim=none; dmarc=pass header.from=evil.example\n"
            "Received: from attacker.example [8.8.8.8] by mx.victim.example; "
            "Tue, 14 Jul 2026 12:00:00 +0900\n"
            "From: PayPal <billing@paypal.com>\nMessage-ID: <test@evil.example>\n\nHello"
        )

        self.assertEqual(result.security.auth.dmarc, "pass")
        self.assertEqual(result.security.auth.dmarc_domain, "evil.example")
        self.assertTrue(
            any("DMARC 認証対象ドメイン" in finding.title for finding in result.security.findings)
        )
        self.assertEqual(result.security.risk_level, "高")

    def test_multiple_from_headers_are_high_risk(self):
        result = analyze_mail_text(
            "From: billing@paypal.com\n"
            "From: attacker@evil.example\n"
            "Subject: test\n\nbody"
        )

        self.assertTrue(
            any("From ヘッダーが複数" in finding.title for finding in result.security.findings)
        )
        self.assertEqual(result.security.risk_level, "高")

    def test_dmarc_pass_without_authenticated_from_domain_is_not_safe(self):
        result = analyze_mail_text(
            "Authentication-Results: mx.victim.example; spf=fail; dkim=none; dmarc=pass\n"
            "Received: from attacker.example [8.8.8.8] by mx.victim.example; "
            "Tue, 14 Jul 2026 12:00:00 +0900\n"
            "From: PayPal <billing@paypal.com>\n\nbody"
        )

        self.assertIsNone(result.security.auth.dmarc_domain)
        self.assertTrue(
            any("DMARC 認証対象ドメインを確認できません" in finding.title for finding in result.security.findings)
        )
        self.assertNotEqual(result.security.risk_level, "問題なし")

    def test_internal_received_id_does_not_hide_trusted_receiver(self):
        result = analyze_mail_text(
            "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=example.com; "
            "dkim=pass header.d=example.com; dmarc=pass header.from=example.com\n"
            "Received: by 2002:a05:internal::1 with SMTP id test; "
            "Tue, 14 Jul 2026 12:00:01 +0900\n"
            "Received: from mail.example.com [8.8.8.8] by mx.google.com; "
            "Tue, 14 Jul 2026 12:00:00 +0900\n"
            "From: Sender <sender@example.com>\nMessage-ID: <test@example.com>\n\nHello"
        )

        self.assertEqual(result.security.auth.source, "mx.google.com")
        self.assertEqual(result.security.auth.dmarc, "pass")

    def test_single_label_top_receiver_does_not_trust_lower_attacker_host(self):
        result = analyze_mail_text(
            "Authentication-Results: attacker.example; spf=pass; dkim=pass "
            "header.d=paypal.com; dmarc=pass header.from=paypal.com\n"
            "Received: from relay.local by localhost; Tue, 14 Jul 2026 12:00:01 +0900\n"
            "Received: from evil.example [8.8.8.8] by attacker.example; "
            "Tue, 14 Jul 2026 12:00:00 +0900\n"
            "From: PayPal <billing@paypal.com>\n\nbody"
        )

        self.assertIsNone(result.security.auth.source)
        self.assertIsNone(result.security.auth.dmarc)

    def test_later_forged_auth_header_cannot_fill_missing_results(self):
        result = analyze_mail_text(
            "Authentication-Results: mx.victim.example; spf=fail smtp.mailfrom=evil.example; "
            "dkim=none\n"
            "Authentication-Results: mx.victim.example; dmarc=pass header.from=paypal.com\n"
            "Received: from attacker.example [8.8.8.8] by mx.victim.example; "
            "Tue, 14 Jul 2026 12:00:00 +0900\n"
            "From: PayPal <billing@paypal.com>\nMessage-ID: <test@evil.example>\n\nHello"
        )

        self.assertEqual(result.security.auth.spf, "fail")
        self.assertEqual(result.security.auth.dkim, "none")
        self.assertIsNone(result.security.auth.dmarc)

    def test_unbound_received_spf_does_not_establish_auth(self):
        result = analyze_mail_text(
            "Received-SPF: pass (attacker supplied)\n"
            "Received: from attacker.example [8.8.8.8] by mx.victim.example; "
            "Tue, 14 Jul 2026 12:00:00 +0900\n"
            "From: PayPal <billing@paypal.com>\nMessage-ID: <test@evil.example>\n\nHello"
        )

        self.assertIsNone(result.security.auth.spf)
        self.assertNotEqual(result.security.risk_level, "問題なし")

    def test_out_of_range_port_is_reported_instead_of_raising(self):
        result = analyze_mail_text(
            "From: sender@example.com\nContent-Type: text/plain; charset=utf-8\n\n"
            "http://example.com:99999/login"
        )

        self.assertEqual(len(result.security.urls), 1)
        self.assertTrue(result.security.urls[0].high_risk)
        self.assertTrue(any("ポート" in flag or "解析" in flag for flag in result.security.urls[0].flags))

    def test_url_without_host_is_reported_as_malformed(self):
        result = analyze_mail_text(
            "From: sender@example.com\nContent-Type: text/plain; charset=utf-8\n\n"
            "http:///login"
        )

        self.assertEqual(len(result.security.urls), 1)
        self.assertTrue(result.security.urls[0].high_risk)
        self.assertTrue(any("ホスト" in flag for flag in result.security.urls[0].flags))

    def test_malformed_anchor_is_reported_instead_of_raising(self):
        result = analyze_mail_text(
            "MIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n"
            '<a href="http://[">https://paypal.com</a>'
        )

        self.assertTrue(result.security.findings)

    def test_scheme_less_displayed_domain_is_compared_with_link_target(self):
        result = analyze_mail_text(
            "MIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n"
            '<a href="https://evil.example/login">paypal.com/login</a>'
        )

        self.assertTrue(
            any("表示上の URL と実際のリンク先" in finding.title for finding in result.security.findings)
        )
        self.assertEqual(result.security.risk_level, "高")

    def test_html_entity_encoded_javascript_uri_is_detected(self):
        result = analyze_mail_text(
            "MIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n"
            '<a href="&#x6a;avascript:alert(1)">open</a>'
        )

        self.assertTrue(
            any("JavaScript" in finding.title for finding in result.security.findings)
        )
        self.assertEqual(result.security.risk_level, "高")

    def test_mixed_timezone_received_dates_do_not_raise(self):
        result = analyze_mail_text(
            "Received: from one.example [8.8.8.8] by mx.example; "
            "Tue, 14 Jul 2026 12:00:00 +0900\n"
            "Received: from two.example [1.1.1.1] by one.example; "
            "Tue, 14 Jul 2026 02:00:00\n"
            "From: sender@example.com\n\nbody"
        )

        self.assertTrue(any("タイムゾーン" in finding.title for finding in result.security.findings))

    def test_unicode_idn_is_high_risk(self):
        result = analyze_mail_text(
            "From: sender@example.com\nContent-Type: text/plain; charset=utf-8\n\n"
            "https://аррӏе.com/login"
        )

        self.assertEqual(len(result.security.urls), 1)
        self.assertTrue(result.security.urls[0].high_risk)
        self.assertTrue(result.security.urls[0].flags)

    def test_ipv6_literal_is_reported_as_direct_ip(self):
        result = analyze_mail_text(
            "From: sender@example.com\nContent-Type: text/plain; charset=utf-8\n\n"
            "https://[2001:db8::1234]/login"
        )

        self.assertEqual(len(result.security.urls), 1)
        self.assertIn("IP アドレス直接指定", result.security.urls[0].flags)

    def test_received_ipv6_is_used_for_origin_estimation(self):
        result = analyze_mail_text(
            "Received: from mail.example (mail.example [IPv6:2606:4700:4700::1111]) "
            "by mx.example; Tue, 14 Jul 2026 12:00:00 +0900\n"
            "From: sender@example.com\n\nbody"
        )

        self.assertEqual(result.security.hops[0].ip, "2606:4700:4700::1111")
        self.assertFalse(result.security.hops[0].ip_is_private)
        self.assertEqual(result.security.origin.ip, "2606:4700:4700::1111")

    def test_windows_trailing_dot_does_not_hide_executable_attachment(self):
        result = analyze_mail_text(
            "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=x\n"
            "From: sender@example.com\n\n"
            "--x\nContent-Type: text/plain\n\nbody\n"
            "--x\nContent-Type: application/octet-stream\n"
            'Content-Disposition: attachment; filename="invoice.exe."\n\n'
            "payload\n--x--\n"
        )

        self.assertTrue(any("実行可能な添付ファイル" in f.title for f in result.security.findings))


if __name__ == "__main__":
    unittest.main()
