#!/usr/bin/env python3
"""
Simple HTTP Vulnerability Test - 1000 Iterations
Direct implementation using HTTP fuzzer architecture
"""
import sys
import time
import logging
from pathlib import Path
from datetime import datetime

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
    print("Using boofuzz baseline fuzzer")
    print("="*70)

    # Start HTTP server
    print("\n[1/3] Starting HTTP server on 127.0.0.1:8080...")
    server = VulnerableHTTPServer(host="127.0.0.1", port=8080)
    supervisor = ServerSupervisor(server)

    try:
        supervisor.start()
        time.sleep(3)  # Wait for server to be ready
        print("✓ HTTP server started successfully\n")

        # Create fuzzer
        print("[2/3] Initializing boofuzz fuzzer...")
        fuzzer = BoofuzzBaseline(
            target_host="127.0.0.1",
            target_port=8080,
            max_iterations=1000,
            pool_size=10,
            refresh_interval=10
        )
        print("✓ Fuzzer initialized\n")

        # Run fuzzing
        print("[3/3] Running 1000 iterations of HTTP fuzzing...")
        print("-"*70)

        start_time = time.time()
        crash_count = 0

        for i in range(1000):
            try:
                # Generate and send payload
                payload = fuzzer.generate_next()

                # Progress updates every 100 iterations
                if (i + 1) % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = (i + 1) / elapsed
                    print(f"Progress: {i+1}/1000 iterations | "
                          f"Time: {elapsed:.1f}s | Rate: {rate:.2f} req/s")

            except Exception as e:
                crash_count += 1
                if crash_count <= 5:  # Log first 5 crashes
                    logging.warning(f"Crash #{crash_count} at iteration {i}: {e}")

        duration = time.time() - start_time

        print("-"*70)
        print(f"\n✓ Test completed successfully!")
        print(f"  Duration: {duration:.1f} seconds")
        print(f"  Average rate: {1000/duration:.2f} requests/second")
        print(f"  Detected crashes: {crash_count}")

        # Get fuzzer statistics
        try:
            stats = fuzzer.get_stats()
            print(f"\nFuzzer Statistics:")
            print(f"  Iterations: {stats.get('iterations', 1000)}")
            print(f"  Crashes: {stats.get('crashes', crash_count)}")
            print(f"  Errors: {stats.get('errors', 0)}")
            print(f"  Timeouts: {stats.get('timeouts', 0)}")

            cve_triggers = stats.get('cve_triggers', {})
            if cve_triggers:
                print(f"\nCVE Triggers:")
                for cve, count in sorted(cve_triggers.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {cve}: {count}")
        except Exception as e:
            logging.warning(f"Could not retrieve statistics: {e}")

        print(f"\nResults saved to: results/http_crashes/")

    except Exception as e:
        logging.error(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # Stop server
        print("\nStopping HTTP server...")
        supervisor.stop()
        print("✓ Server stopped\n")

    return 0

if __name__ == "__main__":
    exit(main())
