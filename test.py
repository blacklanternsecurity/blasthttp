"""Quick manual test — send a single request and inspect the native response."""
import blasthttp
import sys

client = blasthttp.BlastHTTP()

url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
follow = "--follow" in sys.argv or "-L" in sys.argv

r = client.request(url, follow_redirects=follow)

print(f"Status: {r.status}")
print(f"URL:    {r.url}")
print(f"Time:   {r.elapsed_ms}ms")
print(f"Headers ({len(r.headers)}):")
for name, value in r.headers:
    print(f"  {name}: {value}")
if r.redirect_chain:
    print(f"Redirects ({len(r.redirect_chain)}):")
    for hop in r.redirect_chain:
        print(f"  {hop.status} -> {hop.url}")
if r.cert_info:
    print(f"Cert CN:  {r.cert_info.common_name}")
    print(f"Cert SANs: {r.cert_info.sans}")
    print(f"Issuer:   {r.cert_info.issuer}")
    print(f"Fingerprint: {r.cert_info.fingerprint_sha256}")
print(f"Hash:")
print(f"  body_md5:    {r.hash.body_md5}")
print(f"  body_mmh3:   {r.hash.body_mmh3}")
print(f"  body_sha256: {r.hash.body_sha256}")
print(f"Body ({len(r.body)} chars):")
print(r.body[:500])
print(f"\nrepr: {r!r}")
