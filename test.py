import blasthttp
import json
import sys

client = blasthttp.BlastHTTP()

url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
follow = "--follow" in sys.argv or "-L" in sys.argv
verbose = sys.argv.count("-v")

config = {
    "url": url,
    "follow_redirects": follow,
    "verbosity": verbose,
}

resp = json.loads(client.send(json.dumps(config)))

print(f"Status: {resp['status']}")
print(f"URL:    {resp['url']}")
print(f"Time:   {resp['elapsed_ms']}ms")
print(f"Headers ({len(resp['headers'])}):")
for name, value in resp["headers"]:
    print(f"  {name}: {value}")
if resp["redirect_chain"]:
    print(f"Redirects ({len(resp['redirect_chain'])}):")
    for hop in resp["redirect_chain"]:
        print(f"  {hop['status']} -> {hop['url']}")
print(f"Body ({len(resp['body'])} chars):")
print(resp["body"][:500])
