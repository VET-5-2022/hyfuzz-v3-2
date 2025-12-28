#!/usr/bin/env python3
"""
HTTP Vulnerability Test - 1000 Iterations
Using boofuzz baseline fuzzer's run() method
"""
import sys
import time
import logging
import json
from pathlib import Path
from datetime import datetime
from collections import Counter

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Add HTTP directory to path
sys.path.insert(0, str(Path(__file__).parent / "HTTP"))

from target.http_server import VulnerableHTTPServer
from target.supervisor import ServerSupervisor
from fuzzer.boofuzz_baseline import BoofuzzBaseline

def main():
    print("="*70)
    print("HTTP Vulnerability Test - 1000 Iterations")
    print("Framework: boofuzz (Industry Standard)")
    print("="*70)

    # Start HTTP server
    print("\n[Step 1/3] Starting HTTP server on 127.0.0.1:8080...")
    server = VulnerableHTTPServer(host="127.0.0.1", port=8080)
    supervisor = ServerSupervisor(server)

    try:
        supervisor.start()
        time.sleep(3)
        print("✓ HTTP server started successfully\n")

        # Create and run fuzzer
        print("[Step 2/3] Initializing boofuzz baseline fuzzer...")
        fuzzer = BoofuzzBaseline(
            target_host="127.0.0.1",
            target_port=8080,
            max_iterations=1000,
            pool_size=10,
            refresh_interval=10
        )
        print("✓ Fuzzer initialized with 1000 iterations\n")

        print("[Step 3/3] Running 1000 iterations of HTTP fuzzing...")
        print("This will take approximately 10-15 minutes...")
        print("-"*70)

        start_time = time.time()

        # Run fuzzer - this handles everything internally
        result = fuzzer.run(iterations=1000)

        duration = time.time() - start_time

        print("-"*70)
        print(f"\n✓ Test completed!")
        print(f"Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)")

        # Get statistics from result
        print(f"\n{'='*70}")
        print("HTTP VULNERABILITY TEST RESULTS")
        print(f"{'='*70}\n")

        print(f"Iterations Completed: {result.iterations}")
        print(f"Total Crashes: {result.crashes}")
        print(f"CVE Triggers: {result.cve_count}")
        print(f"Unique CVEs Found: {len(result.cve_breakdown)}")
        print(f"Errors: {result.errors}")
        print(f"Timeouts: {result.timeouts}")
        print(f"Average Rate: {result.iterations/duration:.2f} req/s")

        if result.cve_breakdown:
            print(f"\nCVE Breakdown:")
            for cve, count in sorted(result.cve_breakdown.items(),
                                    key=lambda x: x[1], reverse=True):
                percentage = (count / result.cve_count * 100) if result.cve_count > 0 else 0
                print(f"  {cve}: {count} triggers ({percentage:.1f}%)")

        # Save results to JSON
        results_dir = Path("results/http_crashes")
        results_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = results_dir / f"http_test_1000_{timestamp}.json"

        result_data = {
            "target": "HTTP",
            "framework": "boofuzz",
            "iterations": result.iterations,
            "duration_seconds": duration,
            "crashes": result.crashes,
            "cve_triggers": result.cve_count,
            "unique_cves": len(result.cve_breakdown),
            "cve_breakdown": result.cve_breakdown,
            "errors": result.errors,
            "timeouts": result.timeouts,
            "rate_per_second": result.iterations/duration if duration > 0 else 0
        }

        with open(result_file, 'w') as f:
            json.dump(result_data, f, indent=2)

        print(f"\nResults saved to: {result_file}")

        # Try to analyze crash logs if they exist
        cve_trigger_file = results_dir / "cve_triggers.json"
        if cve_trigger_file.exists():
            with open(cve_trigger_file) as f:
                cve_data = json.load(f)
                total_triggers = sum(len(triggers) for triggers in cve_data.values())
                print(f"\nCVE trigger log: {total_triggers} total triggers recorded")

    except Exception as e:
        logging.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        print(f"\n{'='*70}")
        print("Stopping HTTP server...")
        supervisor.stop()
        print("✓ Server stopped")
        print(f"{'='*70}\n")

    return 0

if __name__ == "__main__":
    exit(main())
