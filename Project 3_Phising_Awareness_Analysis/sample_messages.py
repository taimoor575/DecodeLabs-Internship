"""
Sample Messages Dataset - Project 3: Phishing Awareness Analysis
DecodeLabs Cybersecurity Internship | Batch 2026

Each sample is a realistic email/SMS modeled after the attack patterns
described in the training kit (display-name spoofing, lookalike domains,
urgency/authority triggers, BEC, quishing, TOAD callback scams, etc.)
NOTE: All domains, names, and numbers below are fictional/sanitized examples
built for training purposes only.
"""

SAMPLES = [
    {
        "id": "MSG-01",
        "channel": "Email",
        "headers": {
            "from_display": "Microsoft Support",
            "from_address": "support@logins-updates.com",
            "reply_to": "noreply@logins-updates.com",
            "subject": "FW: Urgent Your Account Security Alert"
        },
        "body": (
            "Dear User,\n"
            "We detected unusual sign-in activity on your account. "
            "Your account will be LOCKED in 30 minutes unless you verify your identity immediately. "
            "Click the link below to confirm your password and avoid suspension:\n"
            "http://amaz0n-login-secure.com/verify?id=83920\n"
            "Attachment: Security_Update_2026.iso\n"
            "Do not ignore this message.\n"
            "- Microsoft Account Team"
        )
    },
    {
        "id": "MSG-02",
        "channel": "Email",
        "headers": {
            "from_display": "CEO - STRICTLY CONFIDENTIAL",
            "from_address": "ceo.urgent@executive-update.com",
            "reply_to": "ceo.urgent@executive-update.com",
            "subject": "IMMEDIATE ACTION REQUIRED: Transfer Authorization"
        },
        "body": (
            "I'm in a closed-door meeting and can't talk. "
            "I need you to process an urgent wire transfer of $48,500 to a new vendor account today. "
            "This is time-sensitive and must remain strictly confidential -- do not discuss it with anyone "
            "in finance until it's done. Bypass the standard PO process for this one. "
            "I'll send account details once you confirm you can do this now.\n"
            "Thanks,\n"
            "[CEO Name]"
        )
    },
    {
        "id": "MSG-03",
        "channel": "Email",
        "headers": {
            "from_display": "Sarah Lee (Project Manager)",
            "from_address": "sarah.lee@company.com",
            "reply_to": "sarah.lee@company.com",
            "subject": "Q3 Project Status Update - Non-Urgent"
        },
        "body": (
            "Hi Team,\n"
            "Please review the attached Q3 status report at your earliest convenience. "
            "No immediate action is required, we'll discuss in Thursday's standup.\n"
            "Attachment: Q3_Status.pdf\n"
            "Thanks,\n"
            "Sarah"
        )
    },
    {
        "id": "MSG-04",
        "channel": "SMS",
        "headers": {
            "from_display": "+1-202-555-0114",
            "from_address": "+1-202-555-0114",
            "reply_to": None,
            "subject": None
        },
        "body": (
            "USPS: Your package could not be delivered due to an incomplete address. "
            "Update your delivery info within 24 hours or the package will be returned: "
            "http://usps-track.delivery-update.info/conf?p=44213"
        )
    },
    {
        "id": "MSG-05",
        "channel": "Email",
        "headers": {
            "from_display": "IT Security",
            "from_address": "it-security@company.com",
            "reply_to": "it-security@company.com",
            "subject": "Mandatory: Password expires in 24 hrs"
        },
        "body": (
            "Your network password will expire in 24 hours. "
            "To avoid losing access, reset it now via the company SSO portal: "
            "https://login.company.com/reset (no link shorteners, internal domain). "
            "If you did not request this, contact the IT helpdesk at extension 4521."
        )
    },
    {
        "id": "MSG-06",
        "channel": "Email + Voicemail",
        "headers": {
            "from_display": "Director of Finance",
            "from_address": "director.finance@companygroup-corp.net",
            "reply_to": "director.finance@companygroup-corp.net",
            "subject": "Re: My Voice Message"
        },
        "body": (
            "Hi, I just left you a voicemail (attached audio) regarding the urgent vendor "
            "payment we discussed earlier. Please confirm the updated account number ASAP so "
            "Finance can release the payment before close of business today. Call me only on "
            "this number if you need to verify: +1-555-0199.\n"
            "[Voicemail.mp3 - 0:14]"
        )
    },
    {
        "id": "MSG-07",
        "channel": "Flyer/QR (physical or PDF)",
        "headers": {
            "from_display": "Google Account Recovery",
            "from_address": None,
            "reply_to": None,
            "subject": "Scan to Unlock Your Account"
        },
        "body": (
            "[QR CODE]\n"
            "Google Account Recovery - Scan to Unlock\n"
            "Your account has been flagged for unusual activity. Scan this code with your "
            "phone camera to verify your identity and prevent permanent lockout."
        )
    },
]
