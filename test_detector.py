#!/usr/bin/env python3
"""
Unit Tests for Phishing URL Detector
Author: hemanathan115
"""

import unittest
from phishing_detector import PhishingDetector


class TestPhishingDetector(unittest.TestCase):

    def get_result(self, url):
        d = PhishingDetector(url)
        return d.analyze()

    # ── Safe URLs ──────────────────────────────────────────────────
    def test_safe_https_url(self):
        result = self.get_result("https://www.google.com")
        self.assertLess(result["risk_score"], 30, "Google should be low risk")

    def test_safe_github(self):
        result = self.get_result("https://github.com/hemanathan115")
        self.assertLess(result["risk_score"], 30)

    # ── HTTP flag ──────────────────────────────────────────────────
    def test_http_flag(self):
        result = self.get_result("http://example.com")
        findings_text = " ".join(result["findings"])
        self.assertIn("HTTP", findings_text)

    # ── IP address ─────────────────────────────────────────────────
    def test_ip_address_detection(self):
        result = self.get_result("http://192.168.1.1/login")
        self.assertGreaterEqual(result["risk_score"], 30)

    # ── Brand spoofing ─────────────────────────────────────────────
    def test_brand_spoofing_paypal(self):
        result = self.get_result("http://paypal-secure.com/login")
        self.assertGreaterEqual(result["risk_score"], 50)

    def test_brand_spoofing_amazon(self):
        result = self.get_result("https://amazon-account-verify.xyz")
        self.assertGreaterEqual(result["risk_score"], 50)

    def test_brand_lookalike_domain_is_not_trusted(self):
        result = self.get_result("https://fakepaypal.com")
        self.assertGreaterEqual(result["risk_score"], 35)
        self.assertTrue(any("brand spoofing" in item.lower() for item in result["findings"]))

    def test_real_brand_domain_and_subdomain_are_not_flagged_as_spoofing(self):
        for url in ("https://paypal.com", "https://www.paypal.com"):
            result = self.get_result(url)
            self.assertFalse(any("brand spoofing" in item.lower() for item in result["findings"]))

    # ── Suspicious TLD ─────────────────────────────────────────────
    def test_suspicious_tld_tk(self):
        result = self.get_result("http://freeprize.tk")
        findings_text = " ".join(result["findings"])
        self.assertIn(".tk", findings_text)

    def test_suspicious_tld_xyz(self):
        result = self.get_result("http://win-now.xyz/claim")
        self.assertGreaterEqual(result["risk_score"], 15)

    # ── Keywords ───────────────────────────────────────────────────
    def test_suspicious_keywords(self):
        result = self.get_result("http://fakesite.com/verify-account-login-now")
        findings_text = " ".join(result["findings"])
        self.assertIn("keywords", findings_text.lower())

    # ── Special characters ────────────────────────────────────────
    def test_at_symbol_in_url(self):
        result = self.get_result("http://google.com@evil.com")
        findings_text = " ".join(result["findings"])
        self.assertIn("@", findings_text)

    # ── Long URL ──────────────────────────────────────────────────
    def test_long_url(self):
        long_url = "http://example.com/" + "a" * 120
        result = self.get_result(long_url)
        self.assertGreaterEqual(result["risk_score"], 10)

    # ── High risk combo ───────────────────────────────────────────
    def test_high_risk_combo(self):
        result = self.get_result("http://paypal-secure-login-verify.tk/account?redirect=http://evil.com")
        self.assertGreaterEqual(result["risk_score"], 60, "Should be HIGH risk")

    # ── JSON structure ────────────────────────────────────────────
    def test_result_structure(self):
        result = self.get_result("https://example.com")
        self.assertIn("url", result)
        self.assertIn("risk_score", result)
        self.assertIn("risk_level", result)
        self.assertIn("findings", result)
        self.assertIn("analyzed_at", result)

    def test_rejects_url_without_hostname(self):
        result = self.get_result("https://")
        self.assertEqual(result, {"error": "Invalid URL"})

    def test_rejects_malformed_port(self):
        result = self.get_result("https://example.com:bad")
        self.assertEqual(result, {"error": "Invalid URL"})

    def test_rejects_whitespace_in_url(self):
        result = self.get_result("https://example .com")
        self.assertEqual(result, {"error": "Invalid URL"})


if __name__ == "__main__":
    print("🧪 Running Phishing URL Detector Tests...\n")
    unittest.main(verbosity=2)
