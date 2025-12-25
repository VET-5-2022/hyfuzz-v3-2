"""
Vulnerable FTP Server implementation for fuzzing testing.
Contains simulated CVE vulnerabilities that can be triggered by fuzzer payloads.
"""
import os
import socket
import threading
import logging
import time
from typing import Optional, Dict, Any, Callable, List
from pathlib import Path
from datetime import datetime

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

from .cve_handlers import CVERegistry, CVETriggerResult, CVESeverity
from .crash_logger import CrashLogger, CrashType


class VulnerableFTPHandler(FTPHandler):
    """
    Custom FTP handler with simulated vulnerabilities.
    Intercepts FTP commands and checks for CVE trigger patterns.
    """

    # Class-level attributes to be set by VulnerableFTPServer
    cve_registry: Optional[CVERegistry] = None
    crash_logger: Optional[CrashLogger] = None
    on_crash_callback: Optional[Callable] = None
    fuzzer_type: str = ""
    session_id: str = ""
    iteration: int = 0

    def __init__(self, conn, server, ioloop=None):
        super().__init__(conn, server, ioloop)
        self._command_buffer = b""
        self._last_command = ""
        self._last_args = ""

    def process_command(self, cmd, *args, **kwargs):
        """Override to intercept all FTP commands for CVE checking."""
        # Store command info
        arg_str = args[0] if args else ""
        self._last_command = cmd.upper()
        self._last_args = arg_str
        self._command_buffer = f"{cmd} {arg_str}".encode() if arg_str else cmd.encode()

        # Check for CVE triggers BEFORE processing
        if self.cve_registry:
            results = self.cve_registry.check_all(
                cmd.upper(),
                arg_str,
                self._command_buffer,
                current_state=self._get_protocol_state()
            )
            for result in results:
                self._handle_cve_trigger(result)
                # If CVE was triggered and should crash, don't process command
                if result.should_crash:
                    return

        # Call parent implementation
        try:
            return super().process_command(cmd, *args, **kwargs)
        except Exception as e:
            self._log_crash(str(e), CrashType.PROTOCOL_ERROR)
            raise

    def _get_protocol_state(self) -> str:
        """Get current FTP protocol state for CVE checking."""
        if self.authenticated:
            return "authenticated"
        elif hasattr(self, 'username') and self.username:
            return "user_sent"
        else:
            return "connected"

    def _handle_cve_trigger(self, result: CVETriggerResult):
        """Handle a CVE trigger event."""
        if result.triggered:
            # Log the CVE trigger
            if self.crash_logger:
                cve_handler = self.cve_registry.get_handler(result.cve_id)
                self.crash_logger.log_crash(
                    payload=result.payload,
                    command=self._last_command,
                    arguments=self._last_args,
                    crash_type=CrashType.CVE_TRIGGER,
                    cve_id=result.cve_id,
                    cve_name=cve_handler.cve_info.name if cve_handler else None,
                    error_message=result.error_message,
                    fuzzer_type=self.fuzzer_type,
                    iteration=self.iteration,
                    session_id=self.session_id,
                )

            logging.warning(f"CVE Triggered: {result.cve_id} - {result.error_message}")

            # Send CVE trigger response to client (so fuzzer can detect it)
            # Use 599 as custom code for CVE trigger detection
            try:
                self.respond(f"599 CVE_TRIGGERED:{result.cve_id}:{result.error_message}")
            except Exception:
                pass  # Connection might be closing

            # Simulate crash if needed
            if result.should_crash:
                self._simulate_crash(result)

    def _simulate_crash(self, result: CVETriggerResult):
        """Simulate a server crash for the triggered CVE."""
        logging.error(f"CRASH: {result.cve_id} caused server crash!")

        if self.on_crash_callback:
            self.on_crash_callback(result)

        # Close connection to simulate crash
        self.close()

        # Signal server to restart
        raise ConnectionResetError(f"CVE {result.cve_id} triggered crash")

    def _log_crash(self, error_msg: str, crash_type: CrashType):
        """Log a non-CVE crash."""
        if self.crash_logger:
            self.crash_logger.log_crash(
                payload=self._command_buffer,
                command=self._last_command,
                arguments=self._last_args,
                crash_type=crash_type,
                error_message=error_msg,
                fuzzer_type=self.fuzzer_type,
                iteration=self.iteration,
                session_id=self.session_id,
            )

    # Override specific FTP commands to add vulnerability checks

    def ftp_USER(self, line):
        """USER command with vulnerability check."""
        self._check_buffer_overflow(line, "USER", 256)
        return super().ftp_USER(line)

    def ftp_PASS(self, line):
        """PASS command with vulnerability check."""
        self._check_buffer_overflow(line, "PASS", 256)
        return super().ftp_PASS(line)

    def ftp_CWD(self, path):
        """CWD command with vulnerability check."""
        self._check_path_traversal(path, "CWD")
        self._check_buffer_overflow(path, "CWD", 4096)
        return super().ftp_CWD(path)

    def ftp_RETR(self, file):
        """RETR command with vulnerability check."""
        self._check_path_traversal(file, "RETR")
        return super().ftp_RETR(file)

    def ftp_STOR(self, file):
        """STOR command with vulnerability check."""
        self._check_path_traversal(file, "STOR")
        return super().ftp_STOR(file)

    def ftp_MKD(self, path):
        """MKD command with vulnerability check."""
        self._check_path_traversal(path, "MKD")
        self._check_buffer_overflow(path, "MKD", 256)
        return super().ftp_MKD(path)

    def ftp_RMD(self, path):
        """RMD command with vulnerability check."""
        self._check_path_traversal(path, "RMD")
        return super().ftp_RMD(path)

    def ftp_DELE(self, path):
        """DELE command with vulnerability check."""
        self._check_path_traversal(path, "DELE")
        return super().ftp_DELE(path)

    def ftp_SITE(self, line):
        """SITE command - commonly exploited."""
        # SITE commands are often vectors for vulnerabilities
        if self.crash_logger and ("CPFR" in line.upper() or "CPTO" in line.upper()):
            logging.info(f"SITE command intercepted: {line}")
        return super().ftp_SITE(line)

    def _check_buffer_overflow(self, data: str, command: str, max_len: int):
        """Check for potential buffer overflow."""
        if len(data) > max_len:
            if self.crash_logger:
                self.crash_logger.log_crash(
                    payload=data.encode() if isinstance(data, str) else data,
                    command=command,
                    arguments=data,
                    crash_type=CrashType.PROTOCOL_ERROR,
                    error_message=f"Buffer overflow attempt: {len(data)} > {max_len}",
                    fuzzer_type=self.fuzzer_type,
                    iteration=self.iteration,
                    session_id=self.session_id,
                )

    def _check_path_traversal(self, path: str, command: str):
        """Check for path traversal attempts."""
        traversal_patterns = ["../", "..\\", "%2e%2e", "....//"]
        for pattern in traversal_patterns:
            if pattern in path.lower():
                if self.crash_logger:
                    self.crash_logger.log_crash(
                        payload=path.encode() if isinstance(path, str) else path,
                        command=command,
                        arguments=path,
                        crash_type=CrashType.PROTOCOL_ERROR,
                        error_message=f"Path traversal attempt: {pattern}",
                        fuzzer_type=self.fuzzer_type,
                        iteration=self.iteration,
                        session_id=self.session_id,
                    )
                break


class VulnerableFTPServer:
    """
    FTP Server with simulated CVE vulnerabilities.
    Supports automatic restart after crashes.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2121,
        root_dir: str = "./ftp_root",
        username: str = "anonymous",
        password: str = "anonymous@",
        crash_log_dir: str = "./results/crashes",
        enabled_cves: Optional[List[str]] = None,
    ):
        self.host = host
        self.port = port
        self.root_dir = Path(root_dir)
        self.username = username
        self.password = password

        # Create root directory
        self.root_dir.mkdir(parents=True, exist_ok=True)

        # Create test files
        self._create_test_files()

        # Initialize CVE registry and crash logger
        self.cve_registry = CVERegistry()
        self.crash_logger = CrashLogger(crash_log_dir)

        # Server state
        self.server: Optional[FTPServer] = None
        self._running = False
        self._server_thread: Optional[threading.Thread] = None
        self._crash_count = 0
        self._start_time: Optional[datetime] = None

        # Fuzzer tracking
        self.current_fuzzer_type = ""
        self.current_session_id = ""
        self.current_iteration = 0

    def _create_test_files(self):
        """Create test files in the FTP root directory."""
        # Create some test files for fuzzing
        test_files = {
            "welcome.txt": "Welcome to the vulnerable FTP server!\n",
            "readme.txt": "This is a test file for fuzzing.\n",
            "data/sample.dat": b"\x00\x01\x02\x03\x04\x05" * 100,
            "config/settings.ini": "[server]\nport=2121\nhost=localhost\n",
        }

        for filepath, content in test_files.items():
            full_path = self.root_dir / filepath
            full_path.parent.mkdir(parents=True, exist_ok=True)

            if isinstance(content, bytes):
                full_path.write_bytes(content)
            else:
                full_path.write_text(content)

    def _setup_authorizer(self) -> DummyAuthorizer:
        """Setup FTP authorizer with user permissions."""
        authorizer = DummyAuthorizer()

        # Add configured user (could be anonymous or other)
        if self.username.lower() == "anonymous":
            # Use add_anonymous for anonymous user
            authorizer.add_anonymous(str(self.root_dir), perm="elradfmw")
        else:
            # Add regular user
            authorizer.add_user(
                self.username,
                self.password,
                str(self.root_dir),
                perm="elradfmw"  # Full permissions for testing
            )
            # Also allow anonymous access with limited permissions
            authorizer.add_anonymous(str(self.root_dir), perm="elr")

        return authorizer

    def _setup_handler(self) -> type:
        """Setup FTP handler with vulnerability hooks."""
        # Configure class-level attributes
        VulnerableFTPHandler.cve_registry = self.cve_registry
        VulnerableFTPHandler.crash_logger = self.crash_logger
        VulnerableFTPHandler.on_crash_callback = self._on_crash
        VulnerableFTPHandler.fuzzer_type = self.current_fuzzer_type
        VulnerableFTPHandler.session_id = self.current_session_id
        VulnerableFTPHandler.iteration = self.current_iteration

        # Configure handler
        VulnerableFTPHandler.authorizer = self._setup_authorizer()
        VulnerableFTPHandler.passive_ports = range(60000, 60100)
        VulnerableFTPHandler.banner = "220 Vulnerable FTP Server Ready"

        return VulnerableFTPHandler

    def _on_crash(self, result: CVETriggerResult):
        """Callback when a crash occurs."""
        self._crash_count += 1
        logging.error(f"Crash #{self._crash_count}: {result.cve_id}")

    def start(self, blocking: bool = False):
        """Start the FTP server."""
        if self._running:
            logging.warning("Server is already running")
            return

        handler = self._setup_handler()

        try:
            self.server = FTPServer((self.host, self.port), handler)
            self._running = True
            self._start_time = datetime.now()

            logging.info(f"Starting FTP server on {self.host}:{self.port}")

            if blocking:
                self.server.serve_forever()
            else:
                self._server_thread = threading.Thread(target=self.server.serve_forever)
                self._server_thread.daemon = True
                self._server_thread.start()

        except Exception as e:
            logging.error(f"Failed to start server: {e}")
            self._running = False
            raise

    def stop(self):
        """Stop the FTP server."""
        if self.server:
            logging.info("Stopping FTP server...")
            self.server.close_all()
            self._running = False

            if self._server_thread and self._server_thread.is_alive():
                self._server_thread.join(timeout=5.0)

            self.server = None

    def restart(self, delay: float = 1.0):
        """Restart the FTP server."""
        logging.info(f"Restarting FTP server in {delay}s...")
        self.stop()
        time.sleep(delay)
        self.start()

    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running

    def set_fuzzer_context(self, fuzzer_type: str, session_id: str, iteration: int = 0):
        """Set the current fuzzer context for logging."""
        self.current_fuzzer_type = fuzzer_type
        self.current_session_id = session_id
        self.current_iteration = iteration

        # Update handler class attributes
        VulnerableFTPHandler.fuzzer_type = fuzzer_type
        VulnerableFTPHandler.session_id = session_id
        VulnerableFTPHandler.iteration = iteration

    def update_iteration(self, iteration: int):
        """Update the current iteration counter."""
        self.current_iteration = iteration
        VulnerableFTPHandler.iteration = iteration

    def get_statistics(self) -> Dict[str, Any]:
        """Get server statistics."""
        return {
            "host": self.host,
            "port": self.port,
            "running": self._running,
            "crash_count": self._crash_count,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "uptime_seconds": (datetime.now() - self._start_time).total_seconds() if self._start_time else 0,
            "cve_statistics": self.cve_registry.get_statistics(),
            "crash_statistics": self.crash_logger.get_statistics(),
        }

    def reset_statistics(self):
        """Reset all statistics."""
        self._crash_count = 0
        self.cve_registry.reset_statistics()


def create_server(
    host: str = "127.0.0.1",
    port: int = 2121,
    root_dir: str = "./ftp_root",
) -> VulnerableFTPServer:
    """Factory function to create a vulnerable FTP server."""
    return VulnerableFTPServer(
        host=host,
        port=port,
        root_dir=root_dir,
    )
