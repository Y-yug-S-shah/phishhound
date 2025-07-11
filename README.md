## 🐍 PhishHound – Rule-Based Email Header Analyzer for Phishing Detection

> A lightweight Python CLI tool designed to parse and analyze email headers using rule-based logic. Built for blue teamers, SOC analysts, and threat detection engineers to triage suspicious email reports efficiently.

---

### 📌 Summary

* 🔍 Built to detect phishing indicators in raw email headers (SPF, DKIM, DMARC, Return-Path mismatches, etc.)
* ⚙️ Implements both **heuristic scoring** and **custom rule-based logic** via YAML
* 📁 Supports single header file or folder of `.txt` files for bulk analysis
* 📦 Easily portable and dependency-minimal — no external APIs used
* 🧱 Built using **pure Python 3** and structured in a modular format for extension
* 🔁 Automatically flags common phishing tactics
* 🛠️ Allows fast triage of large inbox phishing reports

---

### 📦 Folder Layout

```
phishhound/
│
├── main.py                      # CLI entry point with banner UI
├── requirements.txt             # Minimal dependencies
├── test_phishhound.sh           # Automated test runner
│
├── phishhound/                  # Modular logic
│   ├── parser.py                # Extracts email fields from headers
│   ├── analyzer.py              # Assigns scores based on heuristics
│   └── rule_engine.py           # Loads and applies YAML rules
│
├── rules/
│   └── phishing_rules.yml       # User-defined detection logic
│
└── sample_headers/
    ├── goodmail.txt
    └── badmail.txt
```

---

### 🔧 Setup & Installation

```bash
git clone https://github.com/Y-yug-S-shah/phishhound.git
cd phishhound
pip install -r requirements.txt
python3 main.py
```

* **Python version**: `>=3.8`
* **Dependencies**: Only `PyYAML` (used for loading rules)

---

### 🚀 How It Works

#### ✅ Header Fields Parsed:

* `Return-Path`
* `From`
* `Reply-To`
* `Received`
* `SPF`, `DKIM`, `DMARC` results

#### ✅ Heuristic Indicators (Base Score):

| Indicator                          | Points |
| ---------------------------------- | ------ |
| `SPF` result is `fail`             | +3     |
| `DKIM` result is `fail`            | +3     |
| `DMARC` result is `none` or `fail` | +2     |
| `Return-Path` ≠ `From` email       | +2     |
| `Reply-To` ≠ `From` email          | +1     |
| `Received` count > 2               | +1     |

#### ✅ Verdict Thresholds:

| Score | Verdict |
| ----- | ------- |
| 0–3   | LOW     |
| 4–6   | MEDIUM  |
| 7+    | HIGH    |

---

### 🧩 Custom Detection Rules

Rules are defined in a simple YAML file: (for understanding purpose, real rules may vary depending on user's/tester's requiremnts)

```yaml
rules:
  - type: from
    pattern: ".*login.*"
    reason: "From header contains generic phishing keywords"
    weight: 2
  - type: return_path
    pattern: ".*\\.xyz$"
    reason: "Return-Path has suspicious newly registered TLD"
    weight: 2
```

🧠 These rules are **applied in addition** to base scoring.

---

### 📁 Sample Usage

#### 📄 Analyze a single file:

```bash
python3 main2.py ../sample_headers/badmail2.eml --export-json
```

#### 📂 Analyze all `.txt` files in a folder:

```bash
python3 main2.py ../sample_headers/
```

---

### 🧪 Sample output

```
📨 Parsed Header Info:

 RETURN_PATH: <spoof@malicious.xyz>
       FROM: Dropbox Alerts <no-reply@dropbox.com>
   REPLY_TO: attacker@gmail.com
        SPF: fail
       DKIM: fail
      DMARC: none

📊 Risk Analysis Summary:
Base Score : 6
Rule Score : 3
Total Score: 9
Verdict    : HIGH
Reasons:
 - SPF failed
 - DKIM failed
 - DMARC missing or failed
 - Return-Path and From mismatch
 - From domain is flagged phishing
```

---

### 🖥️ Example Output

![CLI Tool Banner](assets/screenshot_main_cli.png)
![Header Analysis Output](assets/screenshot_sample_output.png)

---

### 🧠 Built with

* **Python 3.8+**
* Modular structure for CLI tools
* Custom YAML parsing (`PyYAML`)
* SOC-style indicators & phishing TTPs

---

### 📜 License

This project is licensed under the [MIT License](LICENSE)

---

### 👨‍💻 Author

**trailx9** : **Yug Shah**

---

