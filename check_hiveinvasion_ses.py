#!/usr/bin/env python3
"""Check hiveinvasion.games SES verification status."""
import subprocess, json, time

DOMAIN = "hiveinvasion.games"
REGION = "eu-north-1"

def check():
    r = subprocess.run(["aws", "sesv2", "get-email-identity",
        "--email-identity", DOMAIN,
        "--region", REGION, "--no-cli-pager"], capture_output=True, text=True)
    if r.returncode != 0:
        print("Hata:", r.stderr[:200])
        return False
    d = json.loads(r.stdout)
    dkim = d.get("DkimAttributes", {})
    mailfrom = d.get("MailFromAttributes", {})
    sending_ok = d.get("VerifiedForSendingStatus", False)
    dkim_status = dkim.get("Status")
    mf_status = mailfrom.get("MailFromDomainStatus")

    print(f"Domain           : {DOMAIN}")
    print(f"Sending Enabled  : {'✅ YES' if sending_ok else '❌ NO (DNS bekleniyor)'}")
    print(f"DKIM Status      : {'✅ ' if dkim_status == 'SUCCESS' else '⏳ '}{dkim_status}")
    print(f"MailFrom Status  : {'✅ ' if mf_status == 'SUCCESS' else '⏳ '}{mf_status}")
    return sending_ok and dkim_status == "SUCCESS"

if check():
    print("\n🎉 Domain dogrulandi! noreply@hiveinvasion.games uzerinden email gonderilebilir.")
else:
    print("\n⏳ Cloudflare'e DNS kayitlarini ekleyip bu scripti tekrar calistir.")
    print("   Genellikle 1-5 dakika icinde dogrulanır.")
