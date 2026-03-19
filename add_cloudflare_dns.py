#!/usr/bin/env python3
"""Add SES DNS records for hiveinvasion.games via Cloudflare API."""
import urllib.request, urllib.error, json, sys

TOKEN = "c5GsjHJLOo91BNWYRFLBK2Tgq3t7A1Ckkd5ST50H"
DOMAIN = "hiveinvasion.games"
BASE = "https://api.cloudflare.com/client/v4"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

def cf(method, path, body=None):
    url = f"{BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

# 1. Get Zone ID
print(f"Zone aranıyor: {DOMAIN}")
res = cf("GET", f"/zones?name={DOMAIN}&status=active")
if not res.get("success"):
    print("HATA - zones listelenemedi:", res.get("errors"))
    sys.exit(1)

zones = res.get("result", [])
if not zones:
    print(f"HATA: {DOMAIN} zone bulunamadı. Cloudflare'de domain kayıtlı mı?")
    sys.exit(1)

zone_id = zones[0]["id"]
print(f"Zone ID: {zone_id}\n")

# 2. DNS records to add
records = [
    # DKIM CNAMEs
    {"type": "CNAME", "name": "tww3bbwh7d5xyt7wgbsed5brakmx43ap._domainkey", "content": "tww3bbwh7d5xyt7wgbsed5brakmx43ap.dkim.amazonses.com", "proxied": False, "ttl": 1},
    {"type": "CNAME", "name": "ebpsugcecx6qv2nduaspyc42m5lbywtu._domainkey", "content": "ebpsugcecx6qv2nduaspyc42m5lbywtu.dkim.amazonses.com", "proxied": False, "ttl": 1},
    {"type": "CNAME", "name": "bx6f3m3xiucgglh37hjnjtunt5hg4fag._domainkey", "content": "bx6f3m3xiucgglh37hjnjtunt5hg4fag.dkim.amazonses.com", "proxied": False, "ttl": 1},
    # MailFrom MX
    {"type": "MX", "name": "mail", "content": "feedback-smtp.eu-north-1.amazonses.com", "priority": 10, "ttl": 1},
    # SPF TXT
    {"type": "TXT", "name": "mail", "content": "v=spf1 include:amazonses.com ~all", "ttl": 1},
]

print("DNS kayıtları ekleniyor...\n")
success_count = 0
for rec in records:
    r = cf("POST", f"/zones/{zone_id}/dns_records", rec)
    if r.get("success"):
        created = r["result"]
        print(f"  ✅ {created['type']:5s}  {created['name']}")
        success_count += 1
    else:
        errs = r.get("errors", [])
        # Already exists = code 81057
        if any(e.get("code") == 81057 for e in errs):
            print(f"  ℹ️  Zaten mevcut: {rec['type']:5s}  {rec['name']}")
            success_count += 1
        else:
            print(f"  ❌ HATA: {rec['type']:5s}  {rec['name']}  →  {errs}")

print(f"\n{success_count}/{len(records)} kayıt başarılı.")
if success_count == len(records):
    print("\nTüm DNS kayıtları eklendi!")
    print("SES doğrulaması için kontrol et:")
    print("  python3 check_hiveinvasion_ses.py")
