"""
Server Supervisor Module

Provides automatic restart capability for the vulnerable HTTP server.
Monitors server health and restarts it when crashes occur.
"""

import os
import sys
import time
import signal
import threading
import subprocess
from typing import Optional, Callable, Dict, Any
from datetime import datetime
import psutil

from .http_server import VulnerableHTTPServer
from .crash_logger import CrashLogger


class ServerSupervisor:
    """
    Supervisor that monitors and automatically restarts the HTTP server.

    Features:
    - Automatic restart on crash
    - Health monitoring
    - Restart rate limiting
    - Detailed logging
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        restart_delay: float = 1.0,
        max_restarts: int = 100,
        health_check_interval: float = 5.0,
        crash_logger: Optional[CrashLogger] = None,
        on_restart: Optional[Callable[[int], None]] = None,
        simulate_crashes: bool = True
    ):
        """
        Initialize the server supervisor.

        Args:
            host: Host address for the server
            port: Port number for the server
            restart_delay: Delay in seconds before restarting
            max_restarts: Maximum number of automatic restarts
            health_check_interval: Interval for health checks in seconds
            crash_logger: CrashLogger instance
            on_restart: Callback function called on each restart with restart count
            simulate_crashes: Whether to enable crash simulation
        """
        self.host = host
        self.port = port
        self.restart_delay = restart_delay
        self.max_restarts = max_restarts
        self.health_check_interval = health_check_interval
        self.crash_logger = crash_logger or CrashLogger()
        self.on_restart = on_restart
        self.simulate_crashes = simulate_crashes

        # Server instance
        self._server: Optional[VulnerableHTTPServer] = None

        # Supervisor state
        self._running = False
        self._restart_count = 0
        self._total_restarts = 0
        self._last_restart_time: Optional[datetime] = None
        self._start_time: Optional[datetime] = None

        # Threading
        self._supervisor_thread: Optional[threading.Thread] = None
        self._health_check_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Current fuzzer variant
        self._fuzzer_variant: Optional[str] = None

        # Restart history
        self._restart_history: list = []

    def start(self) -> bool:
        """
        Start the supervisor and the HTTP server.

        Returns:
            True if started successfully
        """
        if self._running:
            return False

        self._running = True
        self._start_time = datetime.now()
        self._restart_count = 0

        # Start the server
        self._start_server()

        # Start the supervisor thread
        self._supervisor_thread = threading.Thread(target=self._supervisor_loop)
        self._supervisor_thread.daemon = True
        self._supervisor_thread.start()

        # Start health check thread
        self._health_check_thread = threading.Thread(target=self._health_check_loop)
        self._health_check_thread.daemon = True
        self._health_check_thread.start()

        return True

    def stop(self):
        """Stop the supervisor and the HTTP server."""
        self._running = False

        if self._server:
            self._server.stop()
            self._server = None

        if self._supervisor_thread:
            self._supervisor_thread.join(timeout=5)

        if self._health_check_thread:
            self._health_check_thread.join(timeout=5)

    def _start_server(self) -> bool:
        """
        Start or restart the HTTP server.

        Returns:
            True if server started successfully
        """
        try:
            # Stop existing server if any
            if self._server:
                self._server.stop()

            # Create new server instance
            self._server = VulnerableHTTPServer(
                host=self.host,
                port=self.port,
                crash_logger=self.crash_logger,
                simulate_crashes=self.simulate_crashes,
                fuzzer_variant=self._fuzzer_variant
            )

            # Start the server
            self._server.start(threaded=True)

            return True

        except Exception as e:
            print(f"Failed to start server: {e}")
            return False

    def _supervisor_loop(self):
        """Main supervisor loop that monitors and restarts the server."""
        while self._running:
            try:
                # Check if server is still running
                if self._server and not self._server.is_running():
                    self._handle_server_crash()

                time.sleep(0.5)

            except Exception as e:
                print(f"Supervisor error: {e}")
                time.sleep(1)

    def _health_check_loop(self):
        """Health check loop that periodically verifies server health."""
        import requests

        while self._running:
            try:
                time.sleep(self.health_check_interval)

                if not self._server or not self._server.is_running():
                    continue

                # Perform health check
                try:
                    response = requests.get(
                        f"http://{self.host}:{self.port}/health",
                        timeout=5
                    )
                    if response.status_code != 200:
                        print(f"Health check failed: status {response.status_code}")
                        self._handle_server_crash()
                except requests.exceptions.RequestException as e:
                    print(f"Health check failed: {e}")
                    self._handle_server_crash()

            except Exception as e:
                print(f"Health check error: {e}")

    def _handle_server_crash(self):
        """Handle server crash and restart if allowed."""
        with self._lock:
            if not self._running:
                return

            if self._restart_count >= self.max_restarts:
                print(f"Maximum restarts ({self.max_restarts}) reached. Stopping supervisor.")
                self._running = False
                return

            self._restart_count += 1
            self._total_restarts += 1
            self._last_restart_time = datetime.now()

            # Record restart history
            self._restart_history.append({
                "timestamp": self._last_restart_time.isoformat(),
                "restart_number": self._restart_count,
                "total_restarts": self._total_restarts
            })

            print(f"Server crashed. Restarting ({self._restart_count}/{self.max_restarts})...")

            # Call restart callback if provided
            if self.on_restart:
                try:
                    self.on_restart(self._restart_count)
                except Exception as e:
                    print(f"Restart callback error: {e}")

            # Wait before restart
            time.sleep(self.restart_delay)

            # Restart server
            if self._start_server():
                print(f"Server restarted successfully on {self.host}:{self.port}")
            else:
                print("Failed to restart server")

    def restart_server(self):
        """Manually trigger a server restart."""
        self._handle_server_crash()

    def reset_restart_count(self):
        """Reset the restart counter."""
        with self._lock:
            self._restart_count = 0

    def set_fuzzer_variant(self, variant: str):
        """
        Set the current fuzzer variant for logging.

        Args:
            variant: Name of the fuzzer variant
        """
        self._fuzzer_variant = variant
        if self._server:
            self._server.set_fuzzer_variant(variant)

    def get_status(self) -> Dict[str, Any]:
        """
        Get the supervisor status.

        Returns:
            Dictionary with supervisor status information
        """
        uptime = None
        if self._start_time:
            uptime = (datetime.now() - self._start_time).total_seconds()

        return {
            "running": self._running,
            "server_running": self._server.is_running() if self._server else False,
            "restart_count": self._restart_count,
            "total_restarts": self._total_restarts,
            "max_restarts": self.max_restarts,
            "last_restart": self._last_restart_time.isoformat() if self._last_restart_time else None,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "uptime_seconds": uptime,
            "host": self.host,
            "port": self.port,
            "request_count": self._server.get_request_count() if self._server else 0,
            "fuzzer_variant": self._fuzzer_variant
        }

    def get_restart_history(self) -> list:
        """
        Get the restart history.

        Returns:
            List of restart records
        """
        return self._restart_history.copy()

    def is_running(self) -> bool:
        """Check if the supervisor is running."""
        return self._running

    def get_server(self) -> Optional[VulnerableHTTPServer]:
        """Get the current server instance."""
        return self._server


class ProcessSupervisor:
    """
    Process-based supervisor that runs the server as a separate process.

    This provides better isolation and can handle hard crashes.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        restart_delay: float = 1.0,
        max_restarts: int = 100
    ):
        """
        Initialize the process supervisor.

        Args:
            host: Host address for the server
            port: Port number for the server
            restart_delay: Delay in seconds before restarting
            max_restarts: Maximum number of automatic restarts
        """
        self.host = host
        self.port = port
        self.restart_delay = restart_delay
        self.max_restarts = max_restarts

        self._process: Optional[subprocess.Popen] = None
        self._running = False
        self._restart_count = 0
        self._supervisor_thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Start the process supervisor."""
        if self._running:
            return False

        self._running = True
        self._start_process()

        self._supervisor_thread = threading.Thread(target=self._supervisor_loop)
        self._supervisor_thread.daemon = True
        self._supervisor_thread.start()

        return True

    def stop(self):
        """Stop the process supervisor."""
        self._running = False

        if self._process:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

        if self._supervisor_thread:
            self._supervisor_thread.join(timeout=5)

    def _start_process(self) -> bool:
        """Start the server process."""
        try:
            # Get the path to the http_server module
            module_path = os.path.dirname(os.path.abspath(__file__))

            # Start server as subprocess
            self._process = subprocess.Popen(
                [
                    sys.executable, "-c",
                    f"import sys; sys.path.insert(0, '{os.path.dirname(module_path)}'); "
                    f"from target.http_server import run_server; "
                    f"run_server('{self.host}', {self.port})"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait a bit for server to start
            time.sleep(0.5)

            return self._process.poll() is None

        except Exception as e:
            print(f"Failed to start server process: {e}")
            return False

    def _supervisor_loop(self):
        """Monitor the server process and restart if needed."""
        while self._running:
            try:
                if self._process:
                    # Check if process is still running
                    return_code = self._process.poll()

                    if return_code is not None:
                        # Process has terminated
                        if self._restart_count >= self.max_restarts:
                            print(f"Maximum restarts reached. Stopping.")
                            self._running = False
                            return

                        self._restart_count += 1
                        print(f"Server process exited. Restarting ({self._restart_count}/{self.max_restarts})...")

                        time.sleep(self.restart_delay)
                        self._start_process()

                time.sleep(1)

            except Exception as e:
                print(f"Supervisor error: {e}")
                time.sleep(1)

    def is_running(self) -> bool:
        """Check if the supervisor is running."""
        return self._running


def run_with_supervisor(
    host: str = "127.0.0.1",
    port: int = 8080,
    restart_delay: float = 1.0,
    max_restarts: int = 100
):
    """
    Run the HTTP server with supervisor.

    Args:
        host: Host address
        port: Port number
        restart_delay: Delay before restart
        max_restarts: Maximum restarts allowed
    """
    supervisor = ServerSupervisor(
        host=host,
        port=port,
        restart_delay=restart_delay,
        max_restarts=max_restarts
    )

    def signal_handler(signum, frame):
        print("\nShutting down...")
        supervisor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"Starting supervised HTTP server on {host}:{port}")
    supervisor.start()

    # Keep main thread alive
    try:
        while supervisor.is_running():
            time.sleep(1)
    except KeyboardInterrupt:
        supervisor.stop()


if __name__ == "__main__":
    run_with_supervisor()
