"""
generate_demo_emails.py

Creates a small set of synthetic .eml files for the demo. Several of
them deliberately SHARE infrastructure (same hosting IP / near-identical
domain naming pattern) so the correlation engine has something real to
find and show on the threat graph.

Clearly fake domains only (*.test, *.example, *.invalid — reserved by
RFC 2606, guaranteed to never resolve on the real internet). This is
synthetic training/demo data, not real phishing content.

Run:
    python demo_data/generate_demo_emails.py
Outputs .eml files into demo_data/emails/
"""

import os
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

OUT_DIR = Path(__file__).parent / "emails"

# Shared fake "hosting IP" strings used to link a subset of these emails
# together as one synthetic campaign. Not real IPs (documentation/example
# ranges per RFC 5737).
CAMPAIGN_A_IP = "203.0.113.44"     # TEST-NET-3, reserved/non-routable
CAMPAIGN_A_ASN_NOTE = "AS-EXAMPLE-HOSTING (fictional, for demo)"

EMAILS = [
    {
        "filename": "case1_bank_verify.eml",
        "from_display": "HDFC Bank Security",
        "from_addr": "alerts@secure-verify.test",
        "reply_to": "collect@confirm-login.test",
        "subject": "URGENT: Verify your account within 24 hours",
        "body": (
            "Dear Customer,\n\n"
            "We detected unusual activity on your account. Please verify "
            "your identity immediately to avoid suspension:\n\n"
            "http://secure-verify.test/hdfc/login?ref=8827\n\n"
            f"(hosted at {CAMPAIGN_A_IP})\n\n"
            "Failure to verify within 24 hours will result in account "
            "suspension.\n\nHDFC Bank Security Team"
        ),
        "campaign": "A",
    },
    {
        "filename": "case2_paypal_confirm.eml",
        "from_display": "PayPal Support",
        "from_addr": "no-reply@confirm-login.test",
        "reply_to": "reply@confirm-login.test",
        "subject": "Action required: confirm your payment details",
        "body": (
            "Hello,\n\nWe were unable to process your last transaction. "
            "Please confirm your payment details to restore full account "
            "access:\n\nhttp://confirm-login.test/paypal/confirm?id=5541\n\n"
            f"(hosted at {CAMPAIGN_A_IP})\n\n"
            "PayPal Customer Service"
        ),
        "campaign": "A",
    },
    {
        "filename": "case3_office_update.eml",
        "from_display": "Microsoft Office 365",
        "from_addr": "security@account-check.example",
        "reply_to": "security@account-check.example",
        "subject": "Your password will expire soon",
        "body": (
            "Your Office 365 password expires in 24 hours. Update it now "
            "to avoid losing access:\n\n"
            "http://account-check.example/office365/update?u=3391\n\n"
            f"(hosted at {CAMPAIGN_A_IP})\n\n"
            "Microsoft Account Team"
        ),
        "campaign": "A",
    },
    {
        "filename": "case4_unrelated_newsletter_phish.eml",
        "from_display": "Amazon Prime",
        "from_addr": "prime-deals@totally-different-host.invalid",
        "reply_to": "prime-deals@totally-different-host.invalid",
        "subject": "Your Prime membership: unusual sign-in detected",
        "body": (
            "We noticed a sign-in from a new device. If this wasn't you, "
            "secure your account now:\n\n"
            "http://totally-different-host.invalid/amazon/secure?ref=90\n\n"
            "(hosted at 198.51.100.77)\n\n"
            "This is an unrelated, standalone incident (different "
            "infrastructure) used to show the correlation engine correctly "
            "does NOT group it with Campaign A.\n\nAmazon Security"
        ),
        "campaign": "B",
    },
    {
        "filename": "case5_legit_email.eml",
        "from_display": "Aditya's Team",
        "from_addr": "teammate@thapar.edu",
        "reply_to": "teammate@thapar.edu",
        "subject": "Notes from today's SIH sync",
        "body": (
            "Hey,\n\nSharing notes from today's sync. Nothing urgent, just "
            "documenting progress. See you at the next meeting.\n\nThanks!"
        ),
        "campaign": None,  # control case: should NOT be flagged as phishing
    },
]


def build_eml(spec: dict) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = spec["subject"]
    msg["From"] = f'{spec["from_display"]} <{spec["from_addr"]}>'
    msg["To"] = "employee@example-corp.test"
    msg["Reply-To"] = spec["reply_to"]
    msg["Return-Path"] = spec["reply_to"]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = f'<{spec["filename"]}@demo.local>'

    # Fake but realistic-shaped Received chain (single hop, synthetic)
    msg["Received"] = (
        f'from mail.{spec["from_addr"].split("@")[-1]} '
        f'by mx.example-corp.test with SMTP; {formatdate(localtime=True)}'
    )

    # Fake Authentication-Results header — deliberately shows failures for
    # the phishing cases, passes for the legit control case.
    if spec["campaign"] is None:
        msg["Authentication-Results"] = "mx.example-corp.test; spf=pass; dkim=pass; dmarc=pass"
    else:
        msg["Authentication-Results"] = "mx.example-corp.test; spf=fail; dkim=none; dmarc=fail"

    msg.set_content(spec["body"])
    return msg


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for spec in EMAILS:
        eml = build_eml(spec)
        out_path = OUT_DIR / spec["filename"]
        with open(out_path, "wb") as f:
            f.write(bytes(eml))
        print(f"Wrote {out_path}  (campaign={spec['campaign']})")

    print("\nDone. Campaign A = cases 1-3 (share hosting IP + near-identical")
    print("domain pattern). Case 4 = unrelated. Case 5 = clean control email.")


if __name__ == "__main__":
    main()
