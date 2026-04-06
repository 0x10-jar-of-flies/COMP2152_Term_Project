# ============================================================
#  BLOSSOM CHECK: DNS service HTTPS enforcement + headers
#  Target: dns.0x10.cloud
#  Author: Blossom Babalola, 101606051
# ============================================================
#
#  This script demonstrates an insecure HTTP vulnerability:
#  - HTTP is accessible and does not redirect to HTTPS
#  - Missing HSTS (Strict-Transport-Security) allows downgrade attacks
# ============================================================

import time
import urllib.request

target= "http://dns.0x10.cloud"

print("=" * 50)
print("  HTTPS Enforcement + HSTS Check")
print("=" * 50)

# --- Check 1: HTTP -> HTTPS enforcement ---
print(f"\n  [1] Checking {target} for HTTPS enforcement...")
try:
    response = urllib.request.urlopen(target)
    final_url = response.url
    status = response.status
    headers = dict(response.headers)

    print(f"      Status:     {status}")
    print(f"      Final URL:  {final_url}")
    print(f"      Server:     {headers.get('Server', 'Not disclosed')}")

    if final_url.startswith("http://"):
        print("\n  [!] VULNERABILITY FOUND")
        print("  This site does not enforce HTTPS (HTTP stays enabled).")
        print("  Data can be intercepted/modified by a network attacker.")
    else:
        print("\n  [OK] HTTP redirects to HTTPS.")

    if "Strict-Transport-Security" not in headers:
        print("\n  [!] VULNERABILITY FOUND")
        print("  HSTS is missing (Strict-Transport-Security not set).")
        print("  Attackers can downgrade users to HTTP on first visit.")
    else:
        print("\n  [OK] HSTS is present.")

except Exception as e:
    print(f"\n  [ERROR] Could not connect over HTTP: {e}")

time.sleep(0.15)

print("\n" + "=" * 50)
