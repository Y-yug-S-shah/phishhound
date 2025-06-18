import sys, os, shutil
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
    print("PhishHound++ – Email Header Phishing Analyzer".center(term_width))
    print("Version 1.0 | Author: trailx9\n".center(term_width))


def display_analysis(parsed):
    print("\n📨 Parsed Header Info:\n")
    for k, v in parsed.items():
        label = f"{k.upper():>12}: "
        if isinstance(v, list):
            for item in v:
                print(label + item)
        else:
            print(label + v)

    base = analyze(parsed)
    rule_score, rule_hits = apply_rules(parsed, load_rules())
    total = base['score'] + rule_score
    verdict = "HIGH" if total >= 7 else "MEDIUM" if total >= 4 else "LOW"

    print("\n📊 Risk Analysis Summary:")
    print(f"Base Score : {base['score']}")
    print(f"Rule Score : {rule_score}")
    print(f"Total Score: {total}")
    print(f"Verdict    : {verdict}")
    print("Reasons:")
    for r in base["reasons"] + rule_hits:
        print(f" - {r}")


def run_from_file(path):
    with open(path, 'r') as f:
        display_analysis(parse_headers(f.read()))
