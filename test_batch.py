import blasthttp
import json
import sys
import time

client = blasthttp.BlastHTTP()

urls = [
    "https://example.com",
    "https://httpbin.org/get",
    "https://www.google.com",
    "https://example.org",
]

configs = [{"url": url} for url in urls]

print(f"Sending {len(configs)} requests in batch...")
start = time.time()
results = json.loads(client.send_batch(json.dumps(configs)))
elapsed = time.time() - start

print(f"Got {len(results)} responses in {elapsed:.2f}s\n")

for resp in results:
    print(f"  {resp['status']} {resp['url']} ({resp['elapsed_ms']}ms)")

# Compare with sequential
print(f"\nSending {len(configs)} requests sequentially...")
start = time.time()
for config in configs:
    json.loads(client.send(json.dumps(config)))
elapsed_seq = time.time() - start

print(f"Sequential: {elapsed_seq:.2f}s")
print(f"Batch:      {elapsed:.2f}s")
print(f"Speedup:    {elapsed_seq / elapsed:.1f}x")
