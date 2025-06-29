import sys, os, shutil, argparse, json
from email import message_from_file
from datetime import datetime

sys.path.insert(0, './phishhound')

from parser import parse_headers
from analyzer import analyze
from rule_engine import load_rules, apply_rules

def print_banner():
    term_width = shutil.get_terminal_size((80, 20)).columns
    banner = r"""
    _______  __        _          __       ____  ____                                __  
   |_   __ \[  |      (_)        [  |     |_   ||   _|                              |  ] 
     | |__) || |--.   __   .--.   | |--.    | |__| |   .--.   __   _   _ .--.   .--.| |  
     |  ___/ | .-. | [  | ( (`\]  | .-. |   |  __  | / .'`\ \[  | | | [ `.-. |/ /'`\' |  
    _| |_    | | | |  | |  `'.'.  | | | |  _| |  | |_| \__. | | \_/ |, | | | || \__/  |  
   |_____|  [___]|__][___][\__) )[___]|__]|____||____|'.__.'  '.__.'_/[___||__]'.__.;__] 
    """
    print("\n".join(line.center(term_width) for line in banner.splitlines()))
    print("PhishHound - Email Header Phishing Analyzer".center(term_width))
    print("Version 1.1 | Author: trailx9\n".center(term_width))

def load_headers_from_eml(path):
    with open(path, 'r', errors='ignore') as f:
        msg = message_from_file(f)
    return "\n".join(f"{k}: {v}" for k, v in msg.items())

def get_header_text(path):
    if path.lower().endswith('.eml'):
        return load_headers_from_eml(path)
    else:
        with open(path, 'r', errors='ignore') as f:
            return f.read()

def display_analysis(parsed, explain=False, export_json=False, export_txt=False, filename="output"):
    print("\n📨 Parsed Header Info:\n")
    for k, v in parsed.items():
        label = f"{k.upper():<12}: "
        if isinstance(v, list):
            for item in v:
                print(label + item)
        else:
            print(label + v)

    base = analyze(parsed)
    rule_score, rule_hits = apply_rules(parsed, load_rules())
    total = base['score'] + rule_score
    verdict = "HIGH" if total > 7 else "MEDIUM" if total >= 4 else "LOW"

    print("\n📊 Risk Analysis Summary:")
    print(f"Base Score  : {base['score']}")
    print(f"Rule Score  : {rule_score}")
    print(f"Total Score : {total}")
    print(f"Verdict     : {verdict}")
    print("Reasons:")
    for r in base["reasons"] + rule_hits:
        print(f" - {r}")

    if explain:
        print("\n🔍 Explanation:")
        for reason in base["reasons"]:
            if "spf" in reason.lower():
                print("• SPF failed — sender domain isn't authorized.")
            elif "dkim" in reason.lower():
                print("• DKIM failed — signature mismatch.")
            elif "dmarc" in reason.lower():
                print("• DMARC failed or missing.")
            elif "reply-to" in reason.lower():
                print("• Reply-To mismatch — could redirect response.")
            elif "return-path" in reason.lower():
                print("• Return-Path mismatch — potential spoof.")
        for rule in rule_hits:
            print(f"• Rule matched: {rule}")

    # Exports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = "../reports"
    os.makedirs(out_dir, exist_ok=True)

    if export_json:
        json_path = os.path.join(out_dir, f"{filename}_{timestamp}.json")
        with open(json_path, 'w') as jf:
            json.dump({
                "base_score": base['score'],
                "rule_score": rule_score,
                "total_score": total,
                "verdict": verdict,
                "reasons": base['reasons'] + rule_hits,
                "header_fields": parsed
            }, jf, indent=4)
        print(f"\n📁 Exported JSON to: {json_path}")

    if export_txt:
        txt_path = os.path.join(out_dir, f"{filename}_{timestamp}.txt")
        with open(txt_path, 'w') as tf:
            tf.write("PhishHound CLI - Email Header Analysis\n\n")
            tf.write("Parsed Header Info:\n")
            for k, v in parsed.items():
                if isinstance(v, list):
                    for item in v:
                        tf.write(f"- {k}: {item}\n")
                else:
                    tf.write(f"- {k}: {v}\n")
            tf.write("\nRisk Analysis Summary:\n")
            tf.write(f"- Base Score: {base['score']}\n")
            tf.write(f"- Rule Score: {rule_score}\n")
            tf.write(f"- Total Score: {total}\n")
            tf.write(f"- Verdict: {verdict}\n")
            tf.write("- Reasons:\n")
            for r in base['reasons'] + rule_hits:
                tf.write(f"  • {r}\n")
        print(f"📁 Exported TXT to: {txt_path}")

def run_from_file(path, explain=False, export_json=False, export_txt=False):
    raw = get_header_text(path)
    parsed = parse_headers(raw)
    fname = os.path.splitext(os.path.basename(path))[0]
    display_analysis(parsed, explain, export_json, export_txt, fname)

def run_bulk(folder, explain=False, export_json=False, export_txt=False):
    files = [f for f in os.listdir(folder) if f.endswith('.txt') or f.endswith('.eml')]
    if not files:
        print("No .txt or .eml files found.")
        return
    for fname in files:
        print(f"\n📂 Analyzing: {fname}")
        run_from_file(os.path.join(folder, fname), explain, export_json, export_txt)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishHound - Email Header Analyzer")
    parser.add_argument("--explain", action="store_true", help="Show reasoning for each score/detection")
    parser.add_argument("--export-json", action="store_true", help="Export analysis results to JSON format")
    parser.add_argument("--export-txt", action="store_true", help="Export analysis as plain text")
    parser.add_argument("--version", action="store_true", help="Display version info and exit")
    parser.add_argument("--manual", action="store_true", help="Show detailed usage guide and exit")
    parser.add_argument("path", nargs="?", help="Path to header file or folder")

    args = parser.parse_args()

    # 🔁 Ensure early exit BEFORE anything else
    if args.manual:
        print("""
PhishHound - Email Header Phishing Analyzer (v1.1)
--------------------------------------------------

A lightweight Python CLI tool designed to help SOC analysts and blue teams 
detect phishing attempts based on email header fields.

PhishHound uses heuristic scoring + customizable YAML-based detection rules 
to evaluate metadata like SPF, DKIM, DMARC, Reply-To, Return-Path, etc.

Usage:
  python3 main.py [file_or_folder] [options]

Accepted Inputs:
  - .txt header dumps
  - .eml email files (RFC-822 format)
  - Folders with .txt/.eml files

Flags:
  --explain         Show reasoning for each score/detection
  --export-json     Export analysis results to JSON format
  --export-txt      Export results as plain text
  --manual          Show this help message and exit
  --version         Display version info and exit

Outputs:
  - Risk verdict: LOW / MEDIUM / HIGH
  - Explanation of triggered rules and heuristics
  - Optional export to /phishhound/reports/ (auto-created)

Ideal For:
  - Phishing triage training labs
  - SOC early-stage investigation
  - Detection engineering research

GitHub: https://github.com/Y-yug-S-shah/phishhound
Author : trailx9
        """)
        sys.exit(0)

    if args.version:
        print("PhishHound v1.1 — Rule-based CLI phishing header analyzer")
        sys.exit(0)

    # ✅ Banner prints only after version/manual
    print_banner()

    # Handle missing path
    if not args.path:
        args.path = input("Enter path to header file or folder: ").strip()

    if os.path.isfile(args.path):
        run_from_file(args.path, args.explain, args.export_json, args.export_txt)
    elif os.path.isdir(args.path):
        run_bulk(args.path, args.explain, args.export_json, args.export_txt)
    else:
        print("❌ Invalid input. Provide a valid file or folder.")
