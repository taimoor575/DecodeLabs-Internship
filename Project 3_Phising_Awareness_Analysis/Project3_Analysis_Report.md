# Project 3: Phishing Awareness Analysis
**DecodeLabs Cybersecurity Internship — Defensive Logic / Junior Analyst Track | Batch 2026**

---

## 1. Objective

Analyze a set of sample emails/messages, identify phishing attempts, flag the
suspicious links and keywords that give them away, and explain *why* each
flagged message is unsafe — then turn that judgment into a repeatable triage
process (checklist + decision tree) a non-expert employee could follow.

A companion tool, `phishing_analyzer.py`, implements this logic in code so the
detection rules are explainable and reusable rather than just one-off manual
notes.

---

## 2. Message-by-Message Analysis

### MSG-01 — "Microsoft Account Security Alert" → **MALICIOUS**
- **Suspicious link:** `http://amaz0n-login-secure.com/verify?id=83920`
- **Suspicious keywords:** immediately, locked, suspension, password, verify your identity
- **Red flags:**
  1. *Display-name spoofing* — claims to be "Microsoft Support" but the From
     address is `support@logins-updates.com`, an unrelated domain.
  2. *Reply-To mismatch* — Reply-To differs from the From address, a common
     sign the attacker wants replies routed elsewhere.
  3. *Typosquat/lookalike domain* — `amaz0n-login-secure.com` substitutes a
     zero for the "o" in Amazon and bolts on "-login-secure" (combosquatting).
  4. *Dangerous attachment* — `.iso` files are commonly used to smuggle
     malware past basic email filters.
  5. *Urgency + fear triggers* — artificial 30-minute deadline pressures the
     reader into skipping verification.
- **Why it's unsafe:** Every credibility signal (sender, domain, link) is
  forged, and the message is engineered to make the reader act before they
  think. Clicking the link leads to a credential-harvesting page; opening the
  attachment risks malware execution.

### MSG-02 — "CEO Wire Transfer Request" (BEC / Whaling) → **MALICIOUS**
- **Suspicious keywords:** urgent, strictly confidential, do not discuss, bypass, wire transfer
- **Red flags:**
  1. *Authority impersonation* — poses as the CEO to compel unquestioned compliance.
  2. *Secrecy + procedure-bypass request* — "don't discuss with finance,"
     "bypass the standard PO process" — legitimate finance requests never ask
     to skip controls or stay secret.
  3. *Domain mismatch* — sent from `executive-update.com`, not the real
     corporate domain.
  4. *No verifiable details* — withholds account info until the target
     "confirms," a tactic to avoid early scrutiny.
- **Why it's unsafe:** This is a classic Business Email Compromise (BEC)
  pattern. It targets the finance/admin staff most likely to action a wire
  transfer, exploits perceived executive authority, and explicitly tries to
  prevent the one thing that would catch it — a second person checking.

### MSG-03 — "Q3 Project Status Update" → **SAFE**
- No urgency language (explicitly says "No immediate action is required"),
  sender domain matches the company domain, no links/attachments beyond a
  named, expected PDF.
- **Why it's safe:** Calm tone, internal sender/domain consistency, and no
  request for credentials, money, or bypassed procedure.

### MSG-04 — "USPS Delivery Update" (Smishing) → **MALICIOUS**
- **Suspicious link:** `http://usps-track.delivery-update.info/conf?p=44213`
- **Red flags:**
  1. *Combosquatting* — "usps" + "delivery-update" strung together to look
     official.
  2. *High-risk TLD* — `.info` is rarely used by legitimate logistics brands
     and is a common low-cost domain for throwaway phishing infrastructure.
  3. *Urgency* — 24-hour deadline tied to losing a package.
- **Why it's unsafe:** Real delivery problems are tracked from the official
  carrier app/site, never via an unsolicited SMS link to an unrelated domain.
  This is a smishing pattern designed for the small screen, where full URLs
  are harder to inspect.

### MSG-05 — "IT Security: Password Expiry" → **SUSPICIOUS** (Warn User)
- Sender domain matches the company (`it-security@company.com`), and the
  link points to the legitimate internal SSO domain — but it still mentions a
  password reset under a deadline, and provides a verifiable fallback
  (helpdesk extension).
- **Why it's flagged, not cleared:** Password-related deadlines are one of
  the most cloned phishing templates. Even when everything checks out, this
  category should always be sent through the **Verify** step (call the
  helpdesk at the known extension) before clicking, rather than auto-trusted —
  hence "Warn User," not "Safe."

### MSG-06 — "Director of Finance — Voicemail + Account Number Request" → **MALICIOUS**
- **Suspicious keywords:** urgent, asap, before close of business, account number
- **Red flags:**
  1. *Domain mismatch* — `companygroup-corp.net` is not the real corporate domain.
  2. *Deepfake-voice follow-up* — references an attached voicemail to add a
     false sense of legitimacy/urgency (a 2026-era escalation of vishing).
  3. *Out-of-band number trap* — supplies its own "verification" phone number
     instead of a number from the company directory, defeating the entire
     point of out-of-band verification.
  4. *Sensitive financial request* — asks for an updated account number under
     time pressure.
- **Why it's unsafe:** This combines BEC with AI voice-cloning. The fake
  callback number is the most dangerous detail — verifying through a number
  the attacker supplied isn't verification at all.

### MSG-07 — "Google Account Recovery QR Code" (Quishing) → **MALICIOUS**
- **Red flags:**
  1. *Quishing* — pushes the user to scan a QR code rather than click a link,
     specifically to dodge desktop URL filters/link-scanning by moving the
     interaction to an unmanaged personal phone.
  2. *Fear triggers* — "unusual activity," "permanent lockout."
  3. *No way to verify sender* — QR flyers/posters have no header, domain, or
     sender to check at all, which is itself a red flag.
- **Why it's unsafe:** Scanning lands the victim on a phone browser, which
  typically has fewer security controls than a managed desktop, making
  credential theft easier and detection by IT harder.

---

## 3. Consolidated Red-Flag Reference

| # | Red Flag | What to look for |
|---|----------|-------------------|
| 1 | Sender/domain mismatch | Display name says one thing, From address domain says another |
| 2 | Reply-To mismatch | Reply-To differs from the From address |
| 3 | Lookalike/typosquat domains | `amaz0n`, `paypa1`, homoglyphs, extra hyphenated words |
| 4 | Combosquatting | brand name + "secure/login/update/verify" jammed together |
| 5 | Suspicious/high-risk TLD | `.info`, `.xyz`, `.top`, `.click`, `.tk` |
| 6 | Subdomain trap | Long string ending in an unrelated root domain (read right-to-left) |
| 7 | Urgency language | "act now," "24 hours," "locked," "expires" |
| 8 | Authority impersonation | Claims to be CEO, IT, HR, law enforcement |
| 9 | Secrecy / bypass requests | "don't tell anyone," "skip the normal process" |
| 10 | Sensitive-info requests | Asks for passwords, OTPs, account numbers, wire transfers |
| 11 | Dangerous attachments | `.iso`, `.js`, `.scr`, `.exe`, `.hta` |
| 12 | Quishing | Unsolicited QR codes demanding a scan |
| 13 | Callback/TOAD scams | Only a phone number, no link, pressure to call |
| 14 | Deepfake voice/video | AI-generated audio/video used to add false legitimacy |
| 15 | MFA fatigue | Repeated, unprompted push notifications |

---

## 4. Non-Expert Triage Checklist

Anyone — not just security staff — can run through this in under a minute:

1. **Check the sender.** Does the display name match the actual email domain
   when you hover/tap it? If not → suspicious.
2. **Check the tone.** Is it pushing urgency, secrecy, fear, or authority to
   make you act fast? If yes → suspicious.
3. **Check the ask.** Is it requesting a password, code, account number, or
   money transfer? If yes → treat as high-risk regardless of anything else.
4. **Check the link/QR before tapping.** Read the domain right-to-left. Does
   the *true root domain* match the real company/brand? If not → malicious.
5. **Check the channel for verification.** If you need to confirm, use a
   number/contact **you already had**, never one supplied in the message
   itself.
6. **Check attachments.** Unexpected `.iso/.js/.scr/.exe` files → do not open.
7. **When in doubt, don't engage.** Report it instead of replying, clicking,
   or deleting.

---

## 5. Decision Tree (Pause → Verify → Report)

```
                        Incoming Suspicious Message
                                   |
                    --------------------------------
                    |               |               |
                  SAFE         SUSPICIOUS        MALICIOUS
            (sender/domain    (some red flags,   (clear spoofing,
             match, no asks,   none high-risk —    sensitive-info ask,
             no urgency)        e.g. routine        bypass request,
                  |             password resets)    dangerous link/file)
                  |                  |                   |
               CLOSE             WARN USER          BLOCK & ESCALATE
            (no action          (verify via a      (report to security
             needed)             known channel       team immediately,
                                 before acting)       do not click/reply,
                                                       do not just delete —
                                                       reporting lets IT
                                                       purge it org-wide)
```

**Golden rule:** Pause when you notice a cognitive trigger → Verify through a
second, independently-known channel → Report through the proper channel
(never just silently delete, since deletion alone doesn't protect anyone else
who received the same message).

---

## 6. Tooling: `phishing_analyzer.py`

To make this repeatable, the checklist above was encoded into a small
rule-based Python tool (no ML — fully explainable):

- `sample_messages.py` — 7 sample emails/SMS (5 malicious, 1 suspicious, 1 safe)
- `phishing_analyzer.py` — scans each message for:
  - urgency / authority / fear-greed / bypass / sensitive-info keywords
  - lookalike domains, combosquatting, high-risk TLDs
  - sender/display-name vs. domain mismatches
  - dangerous attachment extensions
  - quishing and callback (TOAD) patterns
  - then scores the message and maps it to **Safe → Close**,
    **Suspicious → Warn User**, or **Malicious → Block & Escalate**,
    matching the decision tree on slide 24 of the brief.

Run it with:
```bash
python3 phishing_analyzer.py
```
It prints a full triage report to the console and saves it to
`triage_report_output.txt`.

---

## 7. Key Takeaway

80% of breaches involve phishing, and it takes an attacker an average of 82
seconds to get a first click — the technical perimeter alone cannot close
that gap. The fix isn't fear, it's a fast, repeatable habit: **Pause, Verify,
Report.** Every red flag in this analysis maps to a specific psychological
trigger (urgency, authority, curiosity, fear/greed) — recognizing the trigger
is faster than inspecting every technical detail, and it's the skill this
project is meant to build.
