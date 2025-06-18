import re

def extract_email(field):
    match = re.search(r'<(.+?)>', field)
    return match.group(1).lower() if match else field.strip().lower()

def analyze(p):
    score, notes = 0, []

    if p.get("spf") == "fail":
        score += 3; notes.append("SPF failed")
    if p.get("dkim") == "fail":
        score += 3; notes.append("DKIM failed")
    if p.get("dmarc") in ["none", "fail"]:
        score += 2; notes.append("DMARC missing or failed")

    if p.get("return_path") and p.get("from"):
        if extract_email(p["return_path"]) != extract_email(p["from"]):
            score += 2; notes.append("Return-Path and From mismatch")

    if p.get("reply_to") and p.get("from"):
        if extract_email(p["reply_to"]) != extract_email(p["from"]):
            score += 1; notes.append("From and Reply-To mismatch")

    if len(p.get("received", [])) > 2:
        score += 1; notes.append("Multiple Received headers")

    verdict = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    return {"score": score, "verdict": verdict, "reasons": notes}
