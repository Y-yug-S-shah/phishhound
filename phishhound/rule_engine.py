import yaml, re
from analyzer import extract_email

def load_rules(path="rules/phishing_rules.yml"):
    with open(path) as f:
        return yaml.safe_load(f)["rules"]

def apply_rules(parsed, rules):
    score, hits = 0, []
    for r in rules:
        val = parsed.get(r["type"])
        if not val: continue
        if re.search(r["pattern"], extract_email(val)):
            score += r["weight"]
            hits.append(r["reason"])
    return score, hits
