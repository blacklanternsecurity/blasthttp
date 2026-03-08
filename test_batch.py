"""Quick manual test — batch requests with native API."""
import blasthttp
import time

client = blasthttp.BlastHTTP()

configs = [
    blasthttp.BatchConfig("https://example.com"),
    blasthttp.BatchConfig("https://httpbin.org/get"),
    blasthttp.BatchConfig("https://www.google.com"),
    blasthttp.BatchConfig("https://example.org"),
]

print(f"Sending {len(configs)} requests in batch...")
start = time.time()
results = client.request_batch(configs)
elapsed = time.time() - start

print(f"Got {len(results)} results in {elapsed:.2f}s\n")

for r in results:
    if r.success:
        print(f"  {r.response.status} {r.url} ({r.response.elapsed_ms}ms)")
    else:
        print(f"  ERROR {r.url}: {r.error}")

# Compare with sequential
print(f"\nSending {len(configs)} requests sequentially...")
start = time.time()
for cfg in configs:
    client.request(cfg.url)
elapsed_seq = time.time() - start

print(f"Sequential: {elapsed_seq:.2f}s")
print(f"Batch:      {elapsed:.2f}s")
print(f"Speedup:    {elapsed_seq / elapsed:.1f}x")
