"""
generate_origintrace_emails.py

Builds 5 synthetic .eml files specifically to exercise OriginTrace's relay
reconstruction: each has a multi-hop Received chain (the existing demo
emails only have 1 hop, which isn't enough to show a "journey").

Scenarios:
  1. Spoofed identity        -- From claims a trusted brand; SPF/DKIM fail;
                                 first hop is unrelated infrastructure.
  2. Compromised account     -- SPF/DKIM PASS via a real webmail provider,
                                 but the very first hop is an unfamiliar
                                 residential IP inconsistent with normal use.
  3. Suspicious VPS          -- origin hop resolves (via the demo IP table)
                                 to VPS/cloud-hosting-style infrastructure,
                                 SPF fail.
  4. Legitimate               -- consistent multi-hop chain, monotonic
                                 timestamps, SPF/DKIM/DMARC pass throughout.
  5. Ambiguous                -- some hops parse fine, one hop is malformed/
                                 truncated, no hard auth failure -- genuinely
                                 unclear.

All domains/IPs are RFC 2606 / RFC 5737 reserved ranges (.test/.example/
.invalid, 203.0.113.x / 198.51.100.x) -- guaranteed never to resolve on the
real internet. Synthetic data only.

Run:
    python demo_data/generate_origintrace_emails.py
"""

from pathlib import Path
from email.message import EmailMessage
from email.utils import formatdate

OUT_DIR = Path(__file__).parent / "emails"


def _msg(subject, from_display, from_addr, reply_to, body, received_lines, auth_results, to_addr="employee@example-corp.test"):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_display} <{from_addr}>"
    msg["To"] = to_addr
    msg["Reply-To"] = reply_to
    msg["Return-Path"] = reply_to
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = f"<{subject[:12].lower().replace(' ', '-')}@demo.local>"
    # Received headers are added oldest-first here, but real MTAs PREPEND
    # each new hop, so the header order (top of raw file) is newest-first.
    # msg[...] = value with repeated keys appends in call order, and
    # email.message writes headers in the order they were set, top to
    # bottom of the file. To make the FIRST Received line in the raw file
    # be the *newest* hop (matching real mail), we add them in reverse.
    for line in reversed(received_lines):
        msg["Received"] = line
    msg["Authentication-Results"] = auth_results
    msg.set_content(body)
    return msg


SCENARIOS = []

# 1. SPOOFED IDENTITY -----------------------------------------------------
SCENARIOS.append({
    "filename": "origintrace_spoofed.eml",
    "msg": _msg(
        subject="Immediate action: HDFC account locked",
        from_display="HDFC Bank Security",
        from_addr="alerts@hdfc-bank.test",
        reply_to="collect@random-relay.invalid",
        body=(
            "Dear customer,\n\nYour HDFC account has been locked due to suspicious activity. "
            "Click below to restore access:\n\nhttp://hdfc-bank.test/restore?id=442\n\nHDFC Bank Security"
        ),
        received_lines=[
            # oldest -> newest
            "from unknown-relay-9.random-relay.invalid (unknown-relay-9.random-relay.invalid [198.51.100.9]) "
            "by smtp-out.random-relay.invalid with SMTP id AA01; " + formatdate(localtime=True),
            "from smtp-out.random-relay.invalid (smtp-out.random-relay.invalid [198.51.100.10]) "
            "by mx.example-corp.test with ESMTP id BB02; " + formatdate(localtime=True),
        ],
        auth_results="mx.example-corp.test; spf=fail smtp.mailfrom=hdfc-bank.test; dkim=none; dmarc=fail header.from=hdfc-bank.test",
    ),
})

# 2. COMPROMISED ACCOUNT --------------------------------------------------
SCENARIOS.append({
    "filename": "origintrace_compromised_account.eml",
    "msg": _msg(
        subject="Shared folder: Q3 budget review",
        from_display="Aditya's Colleague",
        from_addr="realcolleague@outlook.com",
        reply_to="realcolleague@outlook.com",
        body=(
            "Hi,\n\nSharing the Q3 budget folder — can you review before Friday?\n\n"
            "http://sharepoint-files.test/budget?doc=771\n\nThanks!"
        ),
        received_lines=[
            # oldest -> newest: unusual residential first hop, then legit outlook relay
            "from host-51-77-203-91.dyn.example-isp.test (host-51-77-203-91.dyn.example-isp.test [203.0.113.91]) "
            "by webmail-relay.outlook.com with HTTP id CC03; " + formatdate(localtime=True),
            "from webmail-relay.outlook.com (webmail-relay.outlook.com [40.97.0.1]) "
            "by mx.example-corp.test with ESMTPS id DD04; " + formatdate(localtime=True),
        ],
        auth_results="mx.example-corp.test; spf=pass smtp.mailfrom=outlook.com; dkim=pass header.d=outlook.com; dmarc=pass",
    ),
})

# 3. SUSPICIOUS VPS INFRASTRUCTURE -----------------------------------------
SCENARIOS.append({
    "filename": "origintrace_suspicious_vps.eml",
    "msg": _msg(
        subject="Invoice overdue — action needed",
        from_display="Billing Dept",
        from_addr="billing@invoice-portal.test",
        reply_to="billing@invoice-portal.test",
        body=(
            "Your invoice #8834 is overdue. Pay immediately to avoid service suspension:\n\n"
            "http://invoice-portal.test/pay?ref=8834\n\n(hosted at 203.0.113.44)\n\nBilling Dept"
        ),
        received_lines=[
            "from vps-8834.cloud-hosting-example.invalid (vps-8834.cloud-hosting-example.invalid [203.0.113.44]) "
            "by relay1.invoice-portal.test with SMTP id EE05; " + formatdate(localtime=True),
            "from relay1.invoice-portal.test (relay1.invoice-portal.test [203.0.113.45]) "
            "by mx.example-corp.test with ESMTP id FF06; " + formatdate(localtime=True),
        ],
        auth_results="mx.example-corp.test; spf=fail smtp.mailfrom=invoice-portal.test; dkim=none; dmarc=fail",
    ),
})

# 4. LEGITIMATE -------------------------------------------------------------
SCENARIOS.append({
    "filename": "origintrace_legitimate.eml",
    "msg": _msg(
        subject="Weekly newsletter: campus events",
        from_display="Thapar Events Desk",
        from_addr="events@thapar.edu",
        reply_to="events@thapar.edu",
        body="Hi,\n\nHere's this week's list of campus events. No action needed.\n\nThapar Events Desk",
        received_lines=[
            "from mail-relay-1.thapar.edu (mail-relay-1.thapar.edu [198.51.100.201]) "
            "by mx-internal.thapar.edu with ESMTP id GG07; " + formatdate(localtime=True),
            "from mx-internal.thapar.edu (mx-internal.thapar.edu [198.51.100.202]) "
            "by mx.example-corp.test with ESMTPS id HH08; " + formatdate(localtime=True),
        ],
        auth_results="mx.example-corp.test; spf=pass smtp.mailfrom=thapar.edu; dkim=pass header.d=thapar.edu; dmarc=pass",
    ),
})

# 5. AMBIGUOUS ---------------------------------------------------------------
SCENARIOS.append({
    "filename": "origintrace_ambiguous.eml",
    "msg": _msg(
        subject="Re: document access request",
        from_display="Support Team",
        from_addr="support@docs-share.test",
        reply_to="support@docs-share.test",
        body=(
            "Hello,\n\nYour requested document access has been granted:\n\n"
            "http://docs-share.test/access?token=9911\n\nSupport Team"
        ),
        received_lines=[
            # This hop is deliberately malformed/truncated -- no ';' timestamp section, no IP.
            "from mail.docs-share.test by relay.docs-share.test",
            "from relay.docs-share.test (relay.docs-share.test [198.51.100.150]) "
            "by mx.example-corp.test with ESMTP id II09; " + formatdate(localtime=True),
        ],
        auth_results="mx.example-corp.test; spf=none; dkim=none; dmarc=none",
    ),
})


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for spec in SCENARIOS:
        out_path = OUT_DIR / spec["filename"]
        with open(out_path, "wb") as f:
            f.write(bytes(spec["msg"]))
        print(f"Wrote {out_path}")
    print("\nDone. 5 OriginTrace demo cases written to demo_data/emails/.")


if __name__ == "__main__":
    main()
