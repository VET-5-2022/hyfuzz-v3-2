"""
Vulnerable HTTP Server for Fuzzing Testing

This server implements 10 CVE vulnerabilities for testing fuzzers.
It includes crash simulation and detailed request logging.
"""

import os
import sys
import json
import signal
import traceback
import threading
from typing import Dict, Any, Optional, Tuple
from flask import Flask, request, Response, jsonify
from werkzeug.serving import make_server

from .cve_handlers import get_all_handlers, CVEHandler
from .crash_logger import CrashLogger


class VulnerableHTTPServer:
    """
    A vulnerable HTTP server that simulates CVE vulnerabilities for fuzzing testing.

    This server intentionally contains vulnerabilities for security testing purposes.
    DO NOT use this server in production environments.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        crash_logger: Optional[CrashLogger] = None,
        simulate_crashes: bool = True,
        fuzzer_variant: Optional[str] = None
    ):
        """
        Initialize the vulnerable HTTP server.

        Args:
            host: Host address to bind to
            port: Port number to listen on
            crash_logger: CrashLogger instance for logging crashes and CVE triggers
            simulate_crashes: Whether to simulate crashes on certain payloads
            fuzzer_variant: Name of the current fuzzer variant (for logging)
        """
        self.host = host
        self.port = port
        self.crash_logger = crash_logger or CrashLogger()
        self.simulate_crashes = simulate_crashes
        self.fuzzer_variant = fuzzer_variant

        # Initialize CVE handlers
        self.cve_handlers = get_all_handlers()

        # Request counter for iteration tracking
        self._request_counter = 0
        self._lock = threading.Lock()

        # Server instance
        self._server = None
        self._server_thread = None
        self._running = False

        # Create Flask app
        self.app = Flask(__name__)
        self._setup_routes()

        # Disable Flask's default logging for cleaner output
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)

    def _setup_routes(self):
        """Set up Flask routes."""

        @self.app.before_request
        def before_request():
            """Pre-request handler for CVE checking."""
            with self._lock:
                self._request_counter += 1

        # Support all common HTTP methods including WebDAV methods that fuzzers might send
        all_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD',
                       'CONNECT', 'TRACE', 'PROPFIND', 'PROPPATCH', 'MKCOL',
                       'COPY', 'MOVE', 'LOCK', 'UNLOCK', 'DEBUG']

        @self.app.route('/', methods=all_methods)
        @self.app.route('/<path:path>', methods=all_methods)
        def handle_request(path: str = ''):
            """Main request handler that checks for CVE triggers."""
            try:
                return self._process_request(path)
            except Exception as e:
                # Handle any processing errors gracefully
                return jsonify({"error": str(e), "status": "error"}), 500

        @self.app.route('/health', methods=['GET'])
        def health_check():
            """Health check endpoint."""
            return jsonify({
                "status": "healthy",
                "request_count": self._request_counter,
                "cve_handlers": len(self.cve_handlers)
            })

        @self.app.route('/stats', methods=['GET'])
        def get_stats():
            """Get server statistics."""
            stats = self.crash_logger.get_statistics()
            stats['request_count'] = self._request_counter
            return jsonify(stats)

        @self.app.route('/reset', methods=['POST'])
        def reset_stats():
            """Reset statistics and start new session."""
            self._request_counter = 0
            self.crash_logger.reset_session()
            for handler in self.cve_handlers:
                handler.reset()
            return jsonify({"status": "reset", "message": "Statistics reset"})

        @self.app.errorhandler(Exception)
        def handle_error(error):
            """Global error handler - handles malformed requests gracefully."""
            try:
                error_trace = traceback.format_exc()

                # Safely extract request info
                try:
                    req_method = request.method
                    req_path = request.path
                    req_headers = dict(request.headers)
                except Exception:
                    req_method = "UNKNOWN"
                    req_path = "/"
                    req_headers = {}

                try:
                    req_body = request.get_data(as_text=True)[:1000]
                except Exception:
                    req_body = "<unreadable>"

                self.crash_logger.log_crash(
                    crash_type="unhandled_exception",
                    payload=self._get_request_payload(),
                    request_method=req_method,
                    request_path=req_path,
                    request_headers=req_headers,
                    request_body=req_body,
                    error_message=str(error),
                    stack_trace=error_trace,
                    fuzzer_variant=self.fuzzer_variant,
                    iteration=self._request_counter
                )
            except Exception:
                pass  # Silently ignore logging errors

            return jsonify({"error": str(error)}), 500

    def _get_request_payload(self) -> str:
        """
        Extract a string representation of the request payload.
        Handles malformed requests gracefully.

        Returns:
            String representation of the request
        """
        try:
            parts = [
                f"{request.method} {request.full_path}",
                f"Headers: {dict(request.headers)}",
            ]

            try:
                body = request.get_data(as_text=True)
                if body:
                    parts.append(f"Body: {body[:1000]}")  # Truncate long bodies
            except Exception:
                parts.append("Body: <unreadable>")

            return "\n".join(parts)
        except Exception as e:
            return f"<failed to extract payload: {e}>"

    def _process_request(self, path: str) -> Response:
        """
        Process incoming request and check for CVE triggers.

        Args:
            path: Request path

        Returns:
            Flask Response object
        """
        triggered_cves = []
        should_crash = False
        crash_type = None

        # Check all CVE handlers
        for handler in self.cve_handlers:
            triggered, payload_info, metadata = handler.check(request)

            if triggered:
                triggered_cves.append({
                    "cve_id": handler.cve_id,
                    "description": handler.description,
                    "payload": payload_info,
                    "metadata": metadata
                })

                # Log the CVE trigger - safely extract request body
                try:
                    req_body = request.get_data(as_text=True)[:1000]
                except Exception:
                    req_body = "<unreadable>"

                self.crash_logger.log_cve_trigger(
                    cve_id=handler.cve_id,
                    cve_description=handler.description,
                    trigger_payload=payload_info or self._get_request_payload(),
                    trigger_metadata=metadata or {},
                    request_method=request.method,
                    request_path=request.full_path,
                    request_headers=dict(request.headers),
                    request_body=req_body,
                    fuzzer_variant=self.fuzzer_variant,
                    iteration=self._request_counter
                )

                # Determine if we should simulate a crash
                if self.simulate_crashes:
                    should_crash, crash_type = self._should_simulate_crash(
                        handler.cve_id, payload_info, metadata
                    )

        # Check for additional crash conditions
        if self.simulate_crashes and not should_crash:
            should_crash, crash_type = self._check_crash_conditions()

        # Simulate crash if needed
        if should_crash:
            return self._simulate_crash(crash_type, triggered_cves)

        # Normal response
        if triggered_cves:
            return jsonify({
                "status": "vulnerable",
                "triggered_cves": triggered_cves,
                "warning": "Security vulnerabilities detected in request"
            }), 200

        return jsonify({
            "status": "ok",
            "path": path,
            "method": request.method
        }), 200

    def _should_simulate_crash(
        self,
        cve_id: str,
        payload: Optional[str],
        metadata: Optional[Dict[str, Any]]
    ) -> Tuple[bool, Optional[str]]:
        """
        Determine if a crash should be simulated for this CVE trigger.

        Args:
            cve_id: The triggered CVE ID
            payload: The trigger payload
            metadata: Trigger metadata

        Returns:
            Tuple of (should_crash, crash_type)
        """
        # Define which CVEs should cause crashes (2024-2025 CVEs)
        crash_cves = {
            "CVE-2024-27316": ("resource_exhaustion", 0.5),   # HTTP/2 CONTINUATION flood DoS
            "CVE-2024-38477": ("segfault", 0.4),              # mod_proxy Null Pointer Dereference
            "CVE-2024-4577": ("server_crash", 0.3),           # PHP CGI RCE
            "CVE-2024-50379": ("server_crash", 0.4),          # Tomcat Race Condition RCE
            "CVE-2025-24813": ("server_crash", 0.5),          # Tomcat Partial PUT RCE
            "CVE-2024-53677": ("segfault", 0.3),              # Struts Path Traversal RCE
        }

        if cve_id in crash_cves:
            crash_type, crash_rate = crash_cves[cve_id]
            import random
            if random.random() < crash_rate:
                return True, crash_type

        return False, None

    def _check_crash_conditions(self) -> Tuple[bool, Optional[str]]:
        """
        Check for general crash conditions in the request.

        Returns:
            Tuple of (should_crash, crash_type)
        """
        try:
            # Check for overly long headers
            for header_name, header_value in request.headers:
                if len(str(header_value)) > 8192:
                    return True, "header_overflow"

            # Check for overly long body (safely)
            try:
                body = request.get_data()
                if len(body) > 10 * 1024 * 1024:  # 10MB
                    return True, "body_overflow"
            except Exception:
                pass  # Body unreadable - that's OK for fuzzing

            # Check for malformed content
            content_type = request.content_type or ""
            if "application/json" in content_type:
                try:
                    request.get_json()
                except Exception:
                    return True, "malformed_json"

            # Check for null bytes in path
            if '\x00' in request.path:
                return True, "null_byte_injection"
        except Exception:
            pass  # Any error checking conditions - ignore

        return False, None

    def _simulate_crash(
        self,
        crash_type: str,
        triggered_cves: list
    ) -> Response:
        """
        Simulate a server crash.

        Args:
            crash_type: Type of crash to simulate
            triggered_cves: List of triggered CVEs

        Returns:
            Response indicating crash
        """
        # Safely extract request body
        try:
            req_body = request.get_data(as_text=True)[:1000]
        except Exception:
            req_body = "<unreadable>"

        # Log the crash
        self.crash_logger.log_crash(
            crash_type=crash_type,
            payload=self._get_request_payload(),
            request_method=request.method,
            request_path=request.full_path,
            request_headers=dict(request.headers),
            request_body=req_body,
            error_message=f"Simulated {crash_type}",
            stack_trace=None,
            fuzzer_variant=self.fuzzer_variant,
            iteration=self._request_counter
        )

        # Prepare response with CVE information
        crash_response = {
            "status": "crashed",
            "crash_type": crash_type,
            "message": f"Server crashed due to {crash_type}",
            "triggered_cves": triggered_cves  # Include CVE information even in crash
        }

        # Simulate different crash types with JSON response
        status_code = 500
        if crash_type == "server_crash":
            status_code = 500
        elif crash_type == "resource_exhaustion":
            status_code = 503
        elif crash_type == "segfault":
            status_code = 500
        elif crash_type == "connection_reset":
            status_code = 502
        else:
            status_code = 500

        return jsonify(crash_response), status_code, {"X-Crash-Type": crash_type}

    def start(self, threaded: bool = True) -> bool:
        """
        Start the HTTP server.

        Args:
            threaded: Whether to run in a separate thread

        Returns:
            True if started successfully
        """
        if self._running:
            return False

        self._server = make_server(self.host, self.port, self.app, threaded=True)
        self._running = True

        if threaded:
            self._server_thread = threading.Thread(target=self._server.serve_forever)
            self._server_thread.daemon = True
            self._server_thread.start()
        else:
            self._server.serve_forever()

        return True

    def stop(self):
        """Stop the HTTP server."""
        if self._server:
            self._server.shutdown()
            self._running = False
            if self._server_thread:
                self._server_thread.join(timeout=5)

    def is_running(self) -> bool:
        """Check if the server is running."""
        return self._running

    def get_request_count(self) -> int:
        """Get the total request count."""
        return self._request_counter

    def set_fuzzer_variant(self, variant: str):
        """Set the current fuzzer variant for logging."""
        self.fuzzer_variant = variant


def run_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    simulate_crashes: bool = True
):
    """
    Run the vulnerable HTTP server as a standalone process.

    Args:
        host: Host address
        port: Port number
        simulate_crashes: Whether to simulate crashes
    """
    logger = CrashLogger()
    server = VulnerableHTTPServer(
        host=host,
        port=port,
        crash_logger=logger,
        simulate_crashes=simulate_crashes
    )

    def signal_handler(signum, frame):
        print("\nShutting down server...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"Starting vulnerable HTTP server on {host}:{port}")
    print("Press Ctrl+C to stop")

    server.start(threaded=False)


if __name__ == "__main__":
    run_server()
