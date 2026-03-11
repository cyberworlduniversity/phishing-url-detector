# 🛡️ Phishing URL Detector

> **Tool #12** in the Security Toolkit — by [@hemanathan115](https://github.com/hemanathan115)

A Python-based command-line tool that analyzes URLs and detects suspicious phishing patterns using rule-based heuristics. No external APIs or dependencies required — runs entirely offline.

---

## 📌 Features

| Check | Description |
|---|---|
| 🔐 HTTPS Check | Flags HTTP (non-secure) URLs |
| 🖥️ IP Address Detection | Detects raw IP addresses used as hostnames |
| 🏷️ Brand Spoofing | Spots fake lookalike domains (e.g., `paypal-secure.com`) |
| 🔡 Keyword Detection | Flags suspicious words like `login`, `verify`, `secure` |
| 🌐 Suspicious TLDs | Warns about `.tk`, `.xyz`, `.top`, etc. |
| 📏 URL Length | Flags abnormally long URLs |
| 🔀 Redirect Parameters | Detects open redirect tricks (`url=`, `goto=`, etc.) |
| 🔣 Special Characters | Detects `@`, `//`, `..` used to mislead users |
| 🔒 Hex Encoding | Spots heavy URL encoding to hide malicious content |
| 🌿 Subdomains | Flags excessive subdomain nesting |

---

## ⚙️ Requirements

- Python **3.7+**
- No third-party packages needed (uses only standard library)

---

## 🚀 Usage

### 1. Single URL (CLI)

```bash
python phishing_detector.py https://paypal-secure-login.tk/verify
```

### 2. JSON Output

```bash
python phishing_detector.py https://example.com --json
```

### 3. Interactive Mode

```bash
python phishing_detector.py
```

You'll get a prompt to enter URLs one at a time or run batch analysis.

### 4. Batch Mode (inside interactive mode)

```
🔗 Enter URL (or command): batch
  Enter URLs one per line. Type 'done' when finished:
  URL: http://192.168.1.1/login
  URL: https://amaz0n-account-verify.xyz
  URL: done
```

---

## 📊 Risk Score

| Score | Level | Meaning |
|---|---|---|
| 0–29 | 🟢 LOW | Appears safe |
| 30–59 | 🟡 MEDIUM | Suspicious — inspect carefully |
| 60–100 | 🔴 HIGH | Likely phishing |

---

## 🖥️ Sample Output

```
============================================================
       🔍 PHISHING URL DETECTOR - REPORT
============================================================
  URL       : http://paypal-secure-login.tk/verify?user=test
  Domain    : paypal-secure-login.tk
  Risk Score: 85/100
  Verdict   : 🔴 HIGH RISK – Likely Phishing
  Analyzed  : 2026-03-11 10:45:23
------------------------------------------------------------
  FINDINGS:
    ⚠️  Uses HTTP (not HTTPS) – insecure connection
    ⚠️  Suspicious keywords found: login, verify, secure
    🚨  Possible brand spoofing: 'paypal' in domain but not 'paypal.com'
    ⚠️  Suspicious TLD detected: '.tk'
    ⚠️  Redirect parameter 'user=' found – possible open redirect
============================================================
```

---

## 📁 Project Structure

```
phishing-url-detector/
├── phishing_detector.py   # Main tool
├── test_detector.py       # Unit tests
├── requirements.txt       # Dependencies (none required)
└── README.md              # This file
```

---

## 🧪 Running Tests

```bash
python test_detector.py
```

---

## 🤝 Contributing

Pull requests are welcome! If you find a new phishing pattern or want to add more detection rules, feel free to open an issue or PR.

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## 👨‍💻 Author

**hemanathan115**  
GitHub: [https://github.com/hemanathan115](https://github.com/hemanathan115)

> ⚠️ This tool is for educational and defensive security purposes only.
