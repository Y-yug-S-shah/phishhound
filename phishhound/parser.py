import re

def parse_headers(header_text):
    parsed = {}
    lines = [l.strip() for l in header_text.splitlines() if l.strip()]

    for line in lines:
        l = line.lower()
        if l.startswith("return-path:"):
            parsed["return_path"] = line.split(":", 1)[1].strip()
        elif l.startswith("from:"):
            parsed["from"] = line.split(":", 1)[1].strip()
        elif l.startswith("reply-to:"):
            parsed["reply_to"] = line.split(":", 1)[1].strip()
        elif "spf=" in l:
            m = re.search(r"spf=([a-z]+)", line, re.I)
            parsed["spf"] = m.group(1).lower() if m else "none"
        elif "dkim=" in l:
            m = re.search(r"dkim=([a-z]+)", line, re.I)
            parsed["dkim"] = m.group(1).lower() if m else "none"
        elif "dmarc=" in l:
            m = re.search(r"dmarc=([a-z]+)", line, re.I)
            parsed["dmarc"] = m.group(1).lower() if m else "none"
        elif l.startswith("received:"):
            parsed.setdefault("received", []).append(line)

    for key in ["spf", "dkim", "dmarc"]:
        parsed.setdefault(key, "none")

    return parsed
