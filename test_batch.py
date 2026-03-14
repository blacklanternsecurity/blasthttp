"""Quick manual test — batch requests with native API."""
import blasthttp
import time

ROUNDS = 10

client = blasthttp.BlastHTTP()

configs = [
    blasthttp.BatchConfig("https://example.com"),
    blasthttp.BatchConfig("https://httpbin.org/get"),
    blasthttp.BatchConfig("https://www.google.com"),
    blasthttp.BatchConfig("https://example.org"),
    blasthttp.BatchConfig("https://www.blacklanternsecurity.com"),
    blasthttp.BatchConfig("https://blog.blacklanternsecurity.com"),
    blasthttp.BatchConfig("https://www.google.com"),
]

batch_times = []
seq_times = []

for i in range(ROUNDS):
    # Batch
    start = time.time()
    results = client.request_batch(configs)
    batch_elapsed = time.time() - start
    batch_times.append(batch_elapsed)

    errors = [r for r in results if not r.success]

    # Sequential
    start = time.time()
    for cfg in configs:
        client.request(cfg.url)
    seq_elapsed = time.time() - start
    seq_times.append(seq_elapsed)

    speedup = seq_elapsed / batch_elapsed if batch_elapsed > 0 else float("inf")
    print(f"  Round {i+1:2d}: batch={batch_elapsed:.3f}s  seq={seq_elapsed:.3f}s  speedup={speedup:.1f}x  errors={len(errors)}")

avg_batch = sum(batch_times) / ROUNDS
avg_seq = sum(seq_times) / ROUNDS
avg_speedup = avg_seq / avg_batch if avg_batch > 0 else float("inf")

print(f"\n{'='*60}")
print(f"  {ROUNDS} rounds × {len(configs)} requests")
print(f"  Avg batch:      {avg_batch:.3f}s")
print(f"  Avg sequential: {avg_seq:.3f}s")
print(f"  Avg speedup:    {avg_speedup:.1f}x")
print(f"{'='*60}")
