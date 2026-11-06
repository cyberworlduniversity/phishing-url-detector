#!/usr/bin/env python3
"""
Phishing URL Detector - Tool #12
Author: hemanathan115
GitHub: https://github.com/hemanathan115
Description: Analyzes URLs for suspicious phishing patterns
"""

import re
import ipaddress
import sys
import json
import urllib.parse
from datetime import datetime

# ─────────────────────────────────────────────
#  PHISHING PATTERN RULES
# ─────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "paypal", "password", "confirm", "ebay", "amazon",
    "apple", "microsoft", "google", "netflix", "support", "suspended",
    "unlock", "urgent", "verify-now", "click-here", "free", "winner"
]

TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "apple.com", "microsoft.com",
    "amazon.com", "paypal.com", "netflix.com", "twitter.com",
    "instagram.com", "linkedin.com", "github.com", "youtube.com"
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".info", ".biz", ".click"
]

# ─────────────────────────────────────────────
#  ANALYSIS ENGINE
# ─────────────────────────────────────────────

class PhishingDetector:
    def __init__(self, url: str):
        self.original_url = url
        self.url = url.strip()
        self.parsed = None
        self.findings = []
        self.score = 0   # Risk score (0–100)

    def parse_url(self) -> bool:
        try:
            if not self.url or any(ch.isspace() for ch in self.url):
                raise ValueError("URL is empty or contains whitespace")
            if not self.url.startswith(("http://", "https://")):
                self.url = "http://" + self.url
            self.parsed = urllib.parse.urlparse(self.url)
            # urlparse accepts malformed inputs such as "https://" without a host.
            # Reject missing hosts and invalid port/bracket syntax before analysis.
            hostname = self.parsed.hostname
            _ = self.parsed.port
            if not hostname:
                raise ValueError("URL must include a valid hostname")
            if self.parsed.scheme not in ("http", "https"):
                raise ValueError("Only HTTP and HTTPS URLs are supported")
            return True
        except (ValueError, TypeError) as e:
            self.findings.append(f"[ERROR] Could not parse URL: {e}")
            return False

    # --- Individual checks ---

    def check_https(self):
        if self.parsed.scheme != "https":
            self.findings.append("⚠️  Uses HTTP (not HTTPS) – insecure connection")
            self.score += 15
        else:
            self.findings.append("✅  Uses HTTPS")

    def check_ip_address(self):
        hostname = self.parsed.hostname or ""
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            return
        self.findings.append("🚨  IP address used as hostname (common in phishing)")
        self.score += 30

    def check_domain_length(self):
        hostname = self.parsed.hostname or ""
        if len(hostname) > 40:
            self.findings.append(f"⚠️  Long domain name ({len(hostname)} chars) – suspicious")
            self.score += 10

    def check_subdomains(self):
        hostname = self.parsed.hostname or ""
        parts = hostname.split(".")
        if len(parts) > 4:
            self.findings.append(f"⚠️  Excessive subdomains ({len(parts)-2}) – often used to mimic legit sites")
            self.score += 20

    def check_suspicious_keywords(self):
        url_lower = self.url.lower()
        found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
        if found:
            self.findings.append(f"⚠️  Suspicious keywords found: {', '.join(found)}")
            self.score += min(len(found) * 8, 25)

    def check_brand_spoofing(self):
        hostname = (self.parsed.hostname or "").lower().rstrip(".")
        # First allow exact trusted domains and their DNS subdomains.
        if any(hostname == brand or hostname.endswith("." + brand)
               for brand in TRUSTED_DOMAINS):
            self.findings.append("✅  No obvious brand spoofing detected")
            return

        for brand in TRUSTED_DOMAINS:
            brand_name = brand.split(".")[0]
            if brand_name in hostname:
                self.findings.append(
                    f"🚨  Possible brand spoofing: '{brand_name}' in domain but not '{brand}'"
                )
                self.score += 35
                return
        self.findings.append("✅  No obvious brand spoofing detected")

    def check_suspicious_tld(self):
        hostname = self.parsed.hostname or ""
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                self.findings.append(f"⚠️  Suspicious TLD detected: '{tld}'")
                self.score += 15
                return

    def check_url_length(self):
        if len(self.url) > 100:
            self.findings.append(f"⚠️  Very long URL ({len(self.url)} chars) – may hide true destination")
            self.score += 10

    def check_special_characters(self):
        suspicious_chars = ["@", "//", "--", ".."]
        found = [c for c in suspicious_chars if c in self.url]
        if "@" in self.url:
            self.findings.append("🚨  '@' symbol in URL – can redirect to a different host")
            self.score += 30
        for char in ["//", "--", ".."]:
            if char in self.url:
                self.findings.append(f"⚠️  Suspicious character sequence '{char}' found in URL")
                self.score += 10

    def check_redirects(self):
        redirect_keywords = ["redirect", "url=", "link=", "goto=", "next=", "target="]
        url_lower = self.url.lower()
        for kw in redirect_keywords:
            if kw in url_lower:
                self.findings.append(f"⚠️  Redirect parameter '{kw}' found – possible open redirect")
                self.score += 15
                return

    def check_hex_encoding(self):
        if re.search(r"%[0-9a-fA-F]{2}", self.url):
            count = len(re.findall(r"%[0-9a-fA-F]{2}", self.url))
            if count > 5:
                self.findings.append(f"⚠️  Heavy URL encoding ({count} encoded chars) – may hide malicious content")
                self.score += 15

    # --- Risk verdict ---

    def verdict(self) -> dict:
        self.score = min(self.score, 100)
        if self.score >= 60:
            risk = "🔴 HIGH RISK – Likely Phishing"
        elif self.score >= 30:
            risk = "🟡 MEDIUM RISK – Suspicious"
        else:
            risk = "🟢 LOW RISK – Appears Safe"
        return {"risk_level": risk, "score": self.score}

    # --- Run all checks ---

    def analyze(self) -> dict:
        if not self.parse_url():
            return {"error": "Invalid URL"}

        self.check_https()
        self.check_ip_address()
        self.check_domain_length()
        self.check_subdomains()
        self.check_suspicious_keywords()
        self.check_brand_spoofing()
        self.check_suspicious_tld()
        self.check_url_length()
        self.check_special_characters()
        self.check_redirects()
        self.check_hex_encoding()

        verdict = self.verdict()

        return {
            "url": self.original_url,
            "parsed_domain": self.parsed.hostname,
            "risk_level": verdict["risk_level"],
            "risk_score": verdict["score"],
            "findings": self.findings,
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }


# ─────────────────────────────────────────────
#  REPORT PRINTER
# ─────────────────────────────────────────────

def print_report(result: dict):
    print("\n" + "="*60)
    print("       🔍 PHISHING URL DETECTOR - REPORT")
    print("="*60)
    print(f"  URL       : {result.get('url')}")
    print(f"  Domain    : {result.get('parsed_domain')}")
    print(f"  Risk Score: {result.get('risk_score')}/100")
    print(f"  Verdict   : {result.get('risk_level')}")
    print(f"  Analyzed  : {result.get('analyzed_at')}")
    print("-"*60)
    print("  FINDINGS:")
    for finding in result.get("findings", []):
        print(f"    {finding}")
    print("="*60 + "\n")


# ─────────────────────────────────────────────
#  BATCH MODE
# ─────────────────────────────────────────────

def batch_analyze(urls: list) -> list:
    results = []
    for url in urls:
        detector = PhishingDetector(url)
        result = detector.analyze()
        results.append(result)
    return results


# ─────────────────────────────────────────────
#  INTERACTIVE MODE
# ─────────────────────────────────────────────

def interactive_mode():
    print("\n" + "="*60)
    print("   ⚠️  PHISHING URL DETECTOR - by hemanathan115")
    print("="*60)
    print("  Commands:")
    print("    • Enter a URL to analyze")
    print("    • Type 'batch' to analyze multiple URLs")
    print("    • Type 'json' to toggle JSON output mode")
    print("    • Type 'quit' to exit")
    print("="*60)

    json_mode = False

    while True:
        try:
            user_input = input("\n🔗 Enter URL (or command): ").strip()

            if not user_input:
                continue
            elif user_input.lower() == "quit":
                print("👋 Goodbye! Stay safe online.")
                break
            elif user_input.lower() == "json":
                json_mode = not json_mode
                print(f"  JSON mode: {'ON' if json_mode else 'OFF'}")
            elif user_input.lower() == "batch":
                print("  Enter URLs one per line. Type 'done' when finished:")
                urls = []
                while True:
                    line = input("  URL: ").strip()
                    if line.lower() == "done":
                        break
                    if line:
                        urls.append(line)
                results = batch_analyze(urls)
                if json_mode:
                    print(json.dumps(results, indent=2))
                else:
                    for r in results:
                        print_report(r)
            else:
                detector = PhishingDetector(user_input)
                result = detector.analyze()
                if json_mode:
                    print(json.dumps(result, indent=2))
                else:
                    print_report(result)

        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            break


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) > 1:
        url_arg = sys.argv[1]
        detector = PhishingDetector(url_arg)
        result = detector.analyze()

        if "--json" in sys.argv:
            print(json.dumps(result, indent=2))
        else:
            print_report(result)
    else:
        interactive_mode()
