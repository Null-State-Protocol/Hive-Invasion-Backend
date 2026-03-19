#!/usr/bin/env python3
import subprocess, json

r = subprocess.run(["aws", "sesv2", "get-configuration-set",
    "--configuration-set-name", "my-first-configuration-set",
    "--region", "eu-north-1", "--no-cli-pager"], capture_output=True, text=True)
if r.returncode == 0:
    d = json.loads(r.stdout)
    print("Configuration Set:")
    print("  ReputationOptions:", d.get("ReputationOptions"))
    print("  SendingOptions:", d.get("SendingOptions"))
    print("  SuppressionOptions:", d.get("SuppressionOptions"))
else:
    print("Hata:", r.stderr[:300])

r2 = subprocess.run(["aws", "sesv2", "get-configuration-set-event-destinations",
    "--configuration-set-name", "my-first-configuration-set",
    "--region", "eu-north-1", "--no-cli-pager"], capture_output=True, text=True)
if r2.returncode == 0:
    d2 = json.loads(r2.stdout)
    dests = d2.get("EventDestinations", [])
    print(f"\nEvent Destinations: {len(dests)} adet")
    for dest in dests:
        print(f"  - {dest.get('Name')}: Enabled={dest.get('Enabled')} Events={dest.get('MatchingEventTypes')}")
else:
    print("Event destinations hatasi:", r2.stderr[:300])
