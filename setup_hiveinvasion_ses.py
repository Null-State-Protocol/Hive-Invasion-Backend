#!/usr/bin/env python3
"""Add hiveinvasion.games domain to AWS SES with Easy DKIM and custom MailFrom."""
import subprocess, json

DOMAIN = "hiveinvasion.games"
REGION = "eu-north-1"
CONFIG_SET = "my-first-configuration-set"

def run(args):
    r = subprocess.run(args, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

# 1. Create identity
print(f"=== SES'e {DOMAIN} ekleniyor ===")
code, out, err = run(["aws", "sesv2", "create-email-identity",
    "--email-identity", DOMAIN,
    "--dkim-signing-attributes", "NextSigningKeyLength=RSA_2048_BIT",
    "--configuration-set-name", CONFIG_SET,
    "--region", REGION, "--no-cli-pager"])

if code == 0:
    d = json.loads(out)
    print(f"Kimlik olusturuldu.")
    print(f"  IdentityType: {d.get('IdentityType')}")
    print(f"  VerifiedForSendingStatus: {d.get('VerifiedForSendingStatus')}")
    dkim = d.get("DkimAttributes", {})
    print(f"  DKIM Status: {dkim.get('Status')}")
    tokens = dkim.get("Tokens", [])
    print()
    print("=== Cloudflare'e eklenecek DKIM CNAME kayitlari ===")
    for t in tokens:
        print(f"  Ad   : {t}._domainkey.{DOMAIN}")
        print(f"  Deger: {t}.dkim.amazonses.com")
        print()
elif "AlreadyExistsException" in err:
    print(f"Domain zaten mevcut, detaylar aliniyor...")
    code2, out2, err2 = run(["aws", "sesv2", "get-email-identity",
        "--email-identity", DOMAIN,
        "--region", REGION, "--no-cli-pager"])
    if code2 == 0:
        d = json.loads(out2)
        dkim = d.get("DkimAttributes", {})
        tokens = dkim.get("Tokens", [])
        print(f"  DKIM Status: {dkim.get('Status')}")
        print(f"  VerifiedForSendingStatus: {d.get('VerifiedForSendingStatus')}")
        print()
        print("=== Cloudflare'e eklenecek DKIM CNAME kayitlari ===")
        for t in tokens:
            print(f"  Ad   : {t}._domainkey.{DOMAIN}")
            print(f"  Deger: {t}.dkim.amazonses.com")
            print()
    else:
        print("Get identity hatasi:", err2[:300])
else:
    print("Hata:", err[:400])

# 2. Set custom MailFrom domain (mail.hiveinvasion.games)
print("=== Custom MailFrom ayarlaniyor (mail.hiveinvasion.games) ===")
code3, out3, err3 = run(["aws", "sesv2", "put-email-identity-mail-from-attributes",
    "--email-identity", DOMAIN,
    "--mail-from-domain", f"mail.{DOMAIN}",
    "--behavior-on-mx-failure", "USE_DEFAULT_VALUE",
    "--region", REGION, "--no-cli-pager"])
if code3 == 0:
    print("  MailFrom domain ayarlandi: mail.hiveinvasion.games")
else:
    print("  MailFrom hatasi (onemli degil):", err3[:200])

print()
print("=== Cloudflare'e eklenecek MX kaydı (MailFrom icin) ===")
print(f"  Tur  : MX")
print(f"  Ad   : mail.{DOMAIN}")
print(f"  Deger: feedback-smtp.{REGION}.amazonses.com")
print(f"  Onc  : 10")
print()
print("=== SPF TXT kaydi (mail subdomain icin) ===")
print(f"  Tur  : TXT")
print(f"  Ad   : mail.{DOMAIN}")
print(f"  Deger: v=spf1 include:amazonses.com ~all")
