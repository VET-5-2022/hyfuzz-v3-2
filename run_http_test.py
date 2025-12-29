#!/usr/bin/env python3
"""
Simple HTTP Vulnerability Test Runner
Runs 1000 iterations of HTTP fuzzing tests
"""
import sys
import time
import logging
from pathlib import Path

# Add HTTP directory to path
sys.path.insert(0, str(Path(__file__).parent / "HTTP"))

from target.http_server import VulnerableHTTPServer
from target.supervisor import ServerSupervisor
from fuzzer.boofuzz_baseline import BoofuzzBaseline

def main():
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("="*60)
    print("HTTP Vulnerability Test - 1000 Iterations")
    print("="*60)

    # Start HTTP server
    print("\nStarting HTTP server on 127.0.0.1:8080...")
    server = VulnerableHTTPServer(host="127.0.0.1", port=8080)
    supervisor = ServerSupervisor(server)
    supervisor.start()

    time.sleep(2)
    print("HTTP server started successfully\n")

    # Create and run fuzzer
    print("Running 1000 iterations of HTTP fuzzing...")
    print("-"*60)

    fuzzer = BoofuzzBaseline(
        target_host="127.0.0.1",
        target_port=8080,
        pool_size=10,
        refresh_interval=10
    )

    # Run 1000 iterations
    start_time = time.time()
    for i in range(1000):
        try:
            payload = fuzzer.generate_next()
            # The fuzzer handles sending and crash detection internally
            if (i + 1) % 100 == 0:
                elapsed = time.time() - start_time
                print(f"Progress: {i+1}/1000 iterations ({elapsed:.1f}s)")
        except Exception as e:
            logging.error(f"Error in iteration {i}: {e}")
            continue

    duration = time.time() - start_time
    print("-"*60)
    print(f"\nTest completed in {duration:.1f} seconds")
    print(f"Results saved to: results/http_crashes/")

    # Stop server
    supervisor.stop()
    print("\nHTTP server stopped")

if __name__ == "__main__":
    main()
