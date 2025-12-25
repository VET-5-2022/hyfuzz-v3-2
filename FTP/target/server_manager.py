"""
Server Manager for handling FTP server lifecycle and auto-restart.
Monitors server health and restarts it automatically after crashes.
"""
import time
import socket
import threading
import logging
from typing import Optional, Callable, Dict, Any
from datetime import datetime
from enum import Enum

from .vulnerable_ftp_server import VulnerableFTPServer


class ServerState(Enum):
    """Server state enumeration."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    CRASHED = "crashed"
    RESTARTING = "restarting"


class ServerManager:
    """
    Manages the FTP server lifecycle with auto-restart capability.
    Monitors server health and handles crash recovery.
    """

    def __init__(
        self,
        server: VulnerableFTPServer,
        restart_delay: float = 1.0,
        max_restart_attempts: int = 10,
        health_check_interval: float = 5.0,
        on_state_change: Optional[Callable[[ServerState], None]] = None,
    ):
        self.server = server
        self.restart_delay = restart_delay
        self.max_restart_attempts = max_restart_attempts
        self.health_check_interval = health_check_interval
        self.on_state_change = on_state_change

        # State tracking
        self._state = ServerState.STOPPED
        self._restart_count = 0
        self._total_restarts = 0
        self._last_crash_time: Optional[datetime] = None
        self._start_time: Optional[datetime] = None

        # Threading
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitoring = threading.Event()
        self._pause_monitoring = threading.Event()  # For pausing health checks
        self._lock = threading.Lock()

        # Statistics
        self._crash_history: list = []

    def pause_health_check(self):
        """Pause health check monitoring (useful during LLM operations)."""
        self._pause_monitoring.set()
        logging.debug("Health check monitoring paused")

    def resume_health_check(self):
        """Resume health check monitoring."""
        self._pause_monitoring.clear()
        logging.debug("Health check monitoring resumed")

    @property
    def state(self) -> ServerState:
        """Get current server state."""
        return self._state

    def _set_state(self, new_state: ServerState):
        """Set server state and notify callback."""
        with self._lock:
            old_state = self._state
            self._state = new_state

            if old_state != new_state:
                logging.info(f"Server state changed: {old_state.value} -> {new_state.value}")
                if self.on_state_change:
                    try:
                        self.on_state_change(new_state)
                    except Exception as e:
                        logging.error(f"State change callback error: {e}")

    def start(self):
        """Start the server and monitoring."""
        if self._state == ServerState.RUNNING:
            logging.warning("Server is already running")
            return

        self._set_state(ServerState.STARTING)

        try:
            self.server.start(blocking=False)
            self._start_time = datetime.now()
            self._restart_count = 0

            # Wait for server to be ready
            if self._wait_for_server_ready():
                self._set_state(ServerState.RUNNING)
                self._start_monitoring()
            else:
                self._set_state(ServerState.CRASHED)
                logging.error("Server failed to start")

        except Exception as e:
            self._set_state(ServerState.CRASHED)
            logging.error(f"Failed to start server: {e}")
            raise

    def stop(self):
        """Stop the server and monitoring."""
        self._stop_monitoring.set()

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)

        self.server.stop()
        self._set_state(ServerState.STOPPED)

    def restart(self):
        """Manually trigger a server restart."""
        self._set_state(ServerState.RESTARTING)
        self._total_restarts += 1

        logging.info(f"Restarting server (attempt {self._restart_count + 1}/{self.max_restart_attempts})")

        self.server.restart(delay=self.restart_delay)

        if self._wait_for_server_ready():
            self._set_state(ServerState.RUNNING)
            return True
        else:
            self._set_state(ServerState.CRASHED)
            return False

    def _wait_for_server_ready(self, timeout: float = 10.0) -> bool:
        """Wait for server to be ready to accept connections."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self._check_server_health():
                return True
            time.sleep(0.5)

        return False

    def _check_server_health(self) -> bool:
        """Check if server is healthy and accepting connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            result = sock.connect_ex((self.server.host, self.server.port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _start_monitoring(self):
        """Start the health monitoring thread."""
        self._stop_monitoring.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def _monitor_loop(self):
        """Main monitoring loop."""
        while not self._stop_monitoring.is_set():
            time.sleep(self.health_check_interval)

            if self._stop_monitoring.is_set():
                break

            # Skip health check if paused (during LLM operations)
            if self._pause_monitoring.is_set():
                continue

            if not self._check_server_health():
                self._handle_crash()

    def _handle_crash(self):
        """Handle a server crash."""
        self._last_crash_time = datetime.now()
        self._crash_history.append({
            "timestamp": self._last_crash_time.isoformat(),
            "restart_count": self._restart_count,
        })

        logging.error(f"Server crash detected at {self._last_crash_time}")
        self._set_state(ServerState.CRASHED)

        # Attempt restart
        if self._restart_count < self.max_restart_attempts:
            self._restart_count += 1
            time.sleep(self.restart_delay)

            if self.restart():
                logging.info("Server successfully restarted")
            else:
                logging.error("Failed to restart server")
        else:
            logging.critical(
                f"Max restart attempts ({self.max_restart_attempts}) reached. "
                "Manual intervention required."
            )

    def wait_for_ready(self, timeout: float = 30.0) -> bool:
        """Wait for server to be in running state."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            if self._state == ServerState.RUNNING:
                return True
            time.sleep(0.5)

        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        return {
            "state": self._state.value,
            "total_restarts": self._total_restarts,
            "current_restart_count": self._restart_count,
            "max_restart_attempts": self.max_restart_attempts,
            "start_time": self._start_time.isoformat() if self._start_time else None,
            "last_crash_time": self._last_crash_time.isoformat() if self._last_crash_time else None,
            "crash_history": self._crash_history,
            "server_statistics": self.server.get_statistics(),
        }

    def reset_restart_counter(self):
        """Reset the restart counter."""
        with self._lock:
            self._restart_count = 0

    def set_fuzzer_context(self, fuzzer_type: str, session_id: str):
        """Set fuzzer context for the managed server."""
        self.server.set_fuzzer_context(fuzzer_type, session_id)

    def update_iteration(self, iteration: int):
        """Update iteration counter for the managed server."""
        self.server.update_iteration(iteration)


class ServerPool:
    """
    Pool of FTP servers for parallel fuzzing.
    Allows running multiple server instances for different fuzzer types.
    """

    def __init__(self, base_port: int = 2121, pool_size: int = 5):
        self.base_port = base_port
        self.pool_size = pool_size
        self._managers: Dict[str, ServerManager] = {}
        self._port_assignments: Dict[str, int] = {}

    def create_server(
        self,
        fuzzer_id: str,
        root_dir: str = "./ftp_root",
    ) -> ServerManager:
        """Create a new server instance for a fuzzer."""
        if fuzzer_id in self._managers:
            return self._managers[fuzzer_id]

        # Find available port
        used_ports = set(self._port_assignments.values())
        port = self.base_port
        while port in used_ports:
            port += 1
            if port > self.base_port + self.pool_size:
                raise RuntimeError("No available ports in pool")

        # Create server
        server = VulnerableFTPServer(
            host="127.0.0.1",
            port=port,
            root_dir=f"{root_dir}_{fuzzer_id}",
        )

        manager = ServerManager(server)
        self._managers[fuzzer_id] = manager
        self._port_assignments[fuzzer_id] = port

        return manager

    def get_manager(self, fuzzer_id: str) -> Optional[ServerManager]:
        """Get server manager for a fuzzer."""
        return self._managers.get(fuzzer_id)

    def get_port(self, fuzzer_id: str) -> Optional[int]:
        """Get port assigned to a fuzzer."""
        return self._port_assignments.get(fuzzer_id)

    def start_all(self):
        """Start all servers in the pool."""
        for manager in self._managers.values():
            manager.start()

    def stop_all(self):
        """Stop all servers in the pool."""
        for manager in self._managers.values():
            manager.stop()

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics for all servers in the pool."""
        return {
            fuzzer_id: manager.get_statistics()
            for fuzzer_id, manager in self._managers.items()
        }
