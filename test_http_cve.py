#!/usr/bin/env python3
"""
Simple HTTP CVE Detection Test
Tests if the HTTP server can detect CVE patterns
"""
import sys
import time
import requests
from pathlib import Path

# Add HTTP directory to path
sys.path.insert(0, str(Path(__file__).parent / "HTTP"))

from target.http_server import VulnerableHTTPServer
from target.supervisor import ServerSupervisor

def test_cve_detection():
    print("Starting HTTP server for CVE detection test...")
    supervisor = ServerSupervisor(host="127.0.0.1", port=8080)

    try:
        supervisor.start()
        time.sleep(2)
        print("✓ Server started\n")

        base_url = "http://127.0.0.1:8080"

        # Test CVE-2024-24795: CRLF Injection
        print("[Test 1] CVE-2024-24795: CRLF Injection")
        try:
            resp = requests.get(f"{base_url}/test?param=%0d%0a", timeout=2)
            print(f"  Status: {resp.status_code}")
            print(f"  Response: {resp.json()}")
            print()
        except Exception as e:
            print(f"  Error: {e}\n")

        # Test CVE-2024-4577: PHP CGI Injection
        print("[Test 2] CVE-2024-4577: PHP CGI Injection")
        try:
            resp = requests.get(f"{base_url}/php-cgi?-d+allow_url_include=1", timeout=2)
            print(f"  Status: {resp.status_code}")
            print(f"  Response: {resp.json()}")
            print()
        except Exception as e:
            print(f"  Error: {e}\n")

        # Test CVE-2024-23897: Jenkins File Read
        print("[Test 3] CVE-2024-23897: Jenkins File Read")
        try:
            resp = requests.get(f"{base_url}/cli?cmd=@/etc/passwd", timeout=2)
            print(f"  Status: {resp.status_code}")
            print(f"  Response: {resp.json()}")
            print()
        except Exception as e:
            print(f"  Error: {e}\n")

        # Test CVE-2024-27316: HTTP/2 CONTINUATION
        print("[Test 4] CVE-2024-27316: HTTP/2 CONTINUATION")
        try:
            headers = {"X-HTTP2-Continuation": "true"}
            # Send 60 requests to exceed threshold
            for i in range(60):
                resp = requests.get(base_url, headers=headers, timeout=2)
            print(f"  Status: {resp.status_code}")
            print(f"  Response: {resp.json()}")
            print()
        except Exception as e:
            print(f"  Error: {e}\n")

        # Test path with CVE pattern in body
        print("[Test 5] CRLF in Referer header")
        try:
            headers = {"Referer": "http://evil.com%0d%0aSet-Cookie: evil=true"}
            resp = requests.get(base_url, headers=headers, timeout=2)
            print(f"  Status: {resp.status_code}")
            print(f"  Response: {resp.json()}")
            print()
        except Exception as e:
            print(f"  Error: {e}\n")

    finally:
        supervisor.stop()
        print("Server stopped")

if __name__ == "__main__":
    test_cve_detection()
