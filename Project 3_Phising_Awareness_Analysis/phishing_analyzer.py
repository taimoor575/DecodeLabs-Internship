import re
from sample_messages import SAMPLES

URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate action", "act now", "within 24 hours",
    "within 30 minutes", "expires", "locked", "suspend", "suspension",
    "time-sensitive", "today", "asap", "before close of business", "final notice"
]

AUTHORITY_KEYWORDS = [
    "ceo", "director", "executive", "law enforcement", "it security",
    "human resources", "confidential", "strictly confidential", "do not discuss"
]

FEAR_GREED_KEYWORDS = [
    "account will be locked", "legal action", "penalty", "unauthorized",
    "unusual activity", "verify your identity", "permanent lockout", "winner", "prize"
]

BYPASS_KEYWORDS = [
    "bypass", "do not discuss", "without informing", "skip the", "no one else",
    "don't tell", "between us"
]

SENSITIVE_INFO_KEYWORDS = [
    "password", "otp", "verification code", "account number", "wire transfer",
    "billing information", "ssn", "social security", "mfa code", "pin"
]

DANGEROUS_ATTACHMENT_EXT = [".iso", ".js", ".scr", ".exe", ".vbs", ".bat", ".hta", ".jar"]

LOOKALIKE_BRAND_PATTERNS = [
    r"amaz[o0]n", r"payp[a@]l", r"micr[o0]s[o0]ft", r"g[o0][o0]gle", r"appl[e3]",
    r"usps", r"fedex", r"netflix", r"chatgpt"
]

URL_REGEX = re.compile(r"https?://[^\s\)]+|www\.[^\s\)]+", re.IGNORECASE)

NEGATION_WINDOW = 12  # chars before a match to check for a negating word

def find_keyword_hits(text, keyword_list):
    """Finds keyword hits, ignoring matches that are explicitly negated
    (e.g. 'no immediate action is required' should NOT count as an urgency trigger)."""
    text_l = text.lower()
    hits = []
    for kw in keyword_list:
        idx = text_l.find(kw)
        if idx == -1:
            continue
        window = text_l[max(0, idx - NEGATION_WINDOW):idx]
        if "no " in window or "not " in window or "n't " in window:
            continue
        hits.append(kw)
    return hits


def extract_urls(text):
    return URL_REGEX.findall(text)


def check_lookalike_domain(url):
    """Flags brand-name lookalikes / typosquatting / suspicious TLD combos."""
    flags = []
    domain = re.sub(r"https?://", "", url, flags=re.IGNORECASE).split("/")[0]
    for pattern in LOOKALIKE_BRAND_PATTERNS:
        brand_clean = pattern.replace(r"[o0]", "o").replace(r"[a@]", "a").replace(r"[e3]", "e")
        if re.search(pattern, domain, re.IGNORECASE) and brand_clean not in domain.lower():
            flags.append(f"Possible lookalike/typosquat of '{brand_clean}' in domain: {domain}")
        elif re.search(pattern, domain, re.IGNORECASE) and "0" in domain:
            flags.append(f"Homoglyph/number substitution detected in domain: {domain}")
    # combosquatting heuristic: brand + security word + hyphens
    if re.search(r"-(secure|login|update|verify|account)", domain, re.IGNORECASE):
        flags.append(f"Combosquatting pattern (brand + security word): {domain}")
    # suspicious TLD heuristic
    if re.search(r"\.(info|xyz|top|click|tk)$", domain, re.IGNORECASE):
        flags.append(f"Uncommon/high-risk TLD: {domain}")
    return flags


def check_header_mismatch(headers):
    flags = []
    display = (headers.get("from_display") or "").lower()
    address = (headers.get("from_address") or "")
    if not address:
        return flags
    domain = address.split("@")[-1].lower() if "@" in address else address

    trusted_brand_terms = ["microsoft", "google", "usps", "ceo", "it security",
                            "human resources", "director", "finance"]
    for term in trusted_brand_terms:
        if term in display:
            # if display claims a trusted brand/role but domain looks external/free/lookalike
            if any(bad in domain for bad in ["gmail.com", "outlook.com", "yahoo.com"]) or \
               re.search(r"-(update|secure|login|corp)", domain):
                flags.append(
                    f"Display-name spoofing: shows '{headers.get('from_display')}' "
                    f"but the real sending domain is '{domain}', which does not match."
                )
    if headers.get("reply_to") and headers.get("reply_to") != address:
        flags.append(f"Reply-To ({headers['reply_to']}) differs from From address ({address}).")
    return flags


def check_attachments(text):
    flags = []
    for ext in DANGEROUS_ATTACHMENT_EXT:
        if ext in text.lower():
            flags.append(f"Dangerous attachment extension found: '{ext}'")
    return flags


def check_qr_or_callback(text):
    flags = []
    t = text.lower()
    if "qr code" in t or "[qr code]" in t or "scan" in t:
        flags.append("Quishing pattern: message asks the user to scan a QR code (bypasses normal URL/link scanning).")
    if "call" in t and ("1-800" in t or re.search(r"\+\d[\d\-]{7,}", t)) and "http" not in t:
        flags.append("Callback/TOAD pattern: message provides only a phone number, no link, pressuring a call.")
    if "voicemail" in t or "voice message" in t:
        flags.append("Possible deepfake-voice follow-up: references an audio voicemail to add false legitimacy.")
    return flags


# ---------------------------------------------------------------------------
# 3. SCORING + TRIAGE DECISION (maps to the kit's Safe/Suspicious/Malicious flow)
# ---------------------------------------------------------------------------

def score_message(sample):
    text = sample["body"]
    headers = sample["headers"]

    red_flags = []
    suspicious_keywords = []
    suspicious_links = []

    urgency_hits = find_keyword_hits(text, URGENCY_KEYWORDS)
    authority_hits = find_keyword_hits(text, AUTHORITY_KEYWORDS)
    fear_hits = find_keyword_hits(text, FEAR_GREED_KEYWORDS)
    bypass_hits = find_keyword_hits(text, BYPASS_KEYWORDS)
    sensitive_hits = find_keyword_hits(text, SENSITIVE_INFO_KEYWORDS)

    suspicious_keywords = list(set(urgency_hits + authority_hits + fear_hits + bypass_hits + sensitive_hits))

    if urgency_hits:
        red_flags.append(f"Urgency triggers: {urgency_hits}")
    if authority_hits:
        red_flags.append(f"Authority/impersonation language: {authority_hits}")
    if fear_hits:
        red_flags.append(f"Fear/greed triggers: {fear_hits}")
    if bypass_hits:
        red_flags.append(f"Procedure-bypass / secrecy request: {bypass_hits}")
    if sensitive_hits:
        red_flags.append(f"Requests sensitive info/financial action: {sensitive_hits}")

    urls = extract_urls(text)
    for url in urls:
        domain_flags = check_lookalike_domain(url)
        if domain_flags:
            suspicious_links.append(url)
            red_flags.extend(domain_flags)
        else:
            suspicious_links.append(url) if False else None  # legitimate-looking links are not flagged

    header_flags = check_header_mismatch(headers)
    red_flags.extend(header_flags)

    attach_flags = check_attachments(text)
    red_flags.extend(attach_flags)

    qr_callback_flags = check_qr_or_callback(text)
    red_flags.extend(qr_callback_flags)

    # ---- Weighted score ----
    score = 0
    score += 2 * len(urgency_hits)
    score += 2 * len(authority_hits)
    score += 2 * len(fear_hits)
    score += 3 * len(bypass_hits)
    score += 2 * len(sensitive_hits)
    score += 4 * len(header_flags)
    score += 4 * sum(1 for f in red_flags if "lookalike" in f.lower() or "homoglyph" in f.lower() or "combosquat" in f.lower() or "TLD" in f)
    score += 5 * len(attach_flags)
    score += 3 * len(qr_callback_flags)

    if score == 0:
        verdict = "SAFE"
    elif score <= 6:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    action = {"SAFE": "Close", "SUSPICIOUS": "Warn User", "MALICIOUS": "Block & Escalate"}[verdict]

    return {
        "score": score,
        "verdict": verdict,
        "action": action,
        "red_flags": red_flags,
        "suspicious_keywords": suspicious_keywords,
        "suspicious_links": suspicious_links,
    }


# ---------------------------------------------------------------------------
# 4. REPORT GENERATION
# ---------------------------------------------------------------------------

def generate_report():
    lines = []
    lines.append("=" * 78)
    lines.append("PROJECT 3: PHISHING AWARENESS ANALYSIS - TRIAGE REPORT")
    lines.append("DecodeLabs Cybersecurity Internship | Batch 2026")
    lines.append("=" * 78)

    for sample in SAMPLES:
        result = score_message(sample)
        lines.append("")
        lines.append(f"--- {sample['id']} ({sample['channel']}) ---")
        lines.append(f"Subject : {sample['headers'].get('subject')}")
        lines.append(f"From    : {sample['headers'].get('from_display')} <{sample['headers'].get('from_address')}>")
        lines.append(f"Verdict : {result['verdict']}  (risk score: {result['score']})")
        lines.append(f"Action  : {result['action']}")

        if result["suspicious_links"]:
            lines.append("Suspicious Links:")
            for url in result["suspicious_links"]:
                lines.append(f"   - {url}")

        if result["suspicious_keywords"]:
            lines.append(f"Suspicious Keywords: {result['suspicious_keywords']}")

        if result["red_flags"]:
            lines.append("Red Flags Identified:")
            for i, flag in enumerate(result["red_flags"], 1):
                lines.append(f"   {i}. {flag}")
        else:
            lines.append("Red Flags Identified: None")

        lines.append("-" * 78)

    return "\n".join(lines)


if __name__ == "__main__":
    report = generate_report()
    print(report)
    with open("triage_report_output.txt", "w") as f:
        f.write(report)
