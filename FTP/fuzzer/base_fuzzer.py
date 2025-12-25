"""
Base fuzzer class that defines the interface for all fuzzer implementations.
Supports both stateless (random command) and stateful (sequence-based) fuzzing.
"""
import uuid
import socket
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Generator, Tuple
from enum import Enum

from utils.metrics import MetricsCollector
from utils.logger import FuzzerLogger


class FuzzerType(Enum):
    """Types of fuzzers available in the framework."""
    BASELINE = "baseline"              # Pure boofuzz
    LLM_SEED = "llm_seed"             # LLM for seed generation
    LLM_MUTATION = "llm_mutation"      # LLM for mutation
    LLM_FULL = "llm_full"             # LLM for both seed and mutation
    FEEDBACK = "feedback"              # Feedback-driven LLM
    STATEFUL = "stateful"              # State machine-based fuzzing


@dataclass
class FTPCommand:
    """Represents an FTP command with its components."""
    name: str
    args: str = ""
    raw: bytes = b""

    def to_bytes(self) -> bytes:
        """Convert to bytes for transmission."""
        if self.raw:
            return self.raw
        cmd = f"{self.name}"
        if self.args:
            cmd += f" {self.args}"
        cmd += "\r\n"
        return cmd.encode()

    @classmethod
    def from_string(cls, s: str) -> "FTPCommand":
        """Create from string."""
        parts = s.strip().split(None, 1)
        name = parts[0] if parts else ""
        args = parts[1] if len(parts) > 1 else ""
        return cls(name=name, args=args)


@dataclass
class FuzzResult:
    """Result of a single fuzz iteration."""
    iteration: int
    command: FTPCommand
    response: bytes
    response_code: int = 0
    success: bool = True
    crashed: bool = False
    cve_triggered: Optional[str] = None
    response_time_ms: float = 0.0
    error_message: str = ""


@dataclass
class FuzzerConfig:
    """Configuration for fuzzer instances."""
    target_host: str = "127.0.0.1"
    target_port: int = 2121
    timeout: float = 5.0
    max_iterations: int = 10000
    username: str = "anonymous"
    password: str = "anonymous@"
    reconnect_on_failure: bool = True
    max_reconnect_attempts: int = 3

    # Stateful fuzzing options
    stateful_mode: bool = True        # Enable state machine tracking
    sequence_mode: bool = True        # Use command sequences instead of single commands
    state_violation_rate: float = 0.1  # Rate of intentional state violations
    min_sequence_length: int = 3      # Minimum commands per sequence
    max_sequence_length: int = 10     # Maximum commands per sequence


class BaseFuzzer(ABC):
    """
    Abstract base class for all fuzzer implementations.
    Provides common functionality and defines the interface.
    Supports both stateless and stateful (state machine-aware) fuzzing.
    """

    # FTP commands that can be fuzzed
    FTP_COMMANDS = [
        "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN",
        "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU",
        "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD",
        "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP",
        "NOOP", "FEAT", "OPTS", "AUTH", "PBSZ", "PROT", "MLST", "MLSD",
    ]

    def __init__(
        self,
        fuzzer_type: FuzzerType,
        config: FuzzerConfig = None,
        metrics_collector: MetricsCollector = None,
    ):
        self.fuzzer_type = fuzzer_type
        self.config = config or FuzzerConfig()
        self.metrics = metrics_collector or MetricsCollector()

        # Session tracking
        self.session_id = str(uuid.uuid4())[:8]
        self.logger = FuzzerLogger(fuzzer_type.value)

        # Connection state
        self._socket: Optional[socket.socket] = None
        self._connected = False
        self._authenticated = False

        # Iteration tracking
        self._current_iteration = 0
        self._results: List[FuzzResult] = []

        # State machine (lazy initialization)
        self._state_machine = None
        self._sequence_generator = None

        # State tracking metrics
        self._state_coverage: Dict[str, int] = {}
        self._transition_coverage: Dict[str, int] = {}

    def _init_state_machine(self):
        """Initialize state machine for stateful fuzzing."""
        if self._state_machine is None and self.config.stateful_mode:
            from .state_machine import FTPStateMachine, FTPSequenceGenerator
            self._state_machine = FTPStateMachine()
            self._sequence_generator = FTPSequenceGenerator(self._state_machine)

    @property
    def state_machine(self):
        """Get the state machine, initializing if needed."""
        if self._state_machine is None:
            self._init_state_machine()
        return self._state_machine

    def get_current_state(self) -> Optional[str]:
        """Get current FTP protocol state."""
        if self._state_machine:
            return self._state_machine.current_state.name
        return None

    def get_valid_commands(self) -> List[str]:
        """Get commands valid in current state."""
        if self._state_machine:
            return self._state_machine.get_valid_commands()
        return self.FTP_COMMANDS

    def update_state(self, command: str, response_code: int):
        """Update state machine after command execution."""
        if self._state_machine:
            old_state = self._state_machine.current_state.name
            new_state = self._state_machine.execute(command, response_code)

            # Track coverage
            self._state_coverage[new_state.name] = self._state_coverage.get(new_state.name, 0) + 1
            transition = f"{old_state}->{command}->{new_state.name}"
            self._transition_coverage[transition] = self._transition_coverage.get(transition, 0) + 1

            return new_state
        return None

    @property
    def name(self) -> str:
        """Get fuzzer name."""
        return self.fuzzer_type.value

    def connect(self) -> bool:
        """Connect to the FTP server."""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.config.timeout)
            self._socket.connect((self.config.target_host, self.config.target_port))
            self._connected = True

            # Read banner
            banner = self._recv()
            logging.debug(f"Connected to FTP server: {banner}")

            # Update state machine
            if self.config.stateful_mode:
                self._init_state_machine()
                if self._state_machine:
                    self._state_machine.set_connected()

            return True
        except Exception as e:
            logging.error(f"Connection failed: {e}")
            self._connected = False
            return False

    def disconnect(self):
        """Disconnect from the FTP server."""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None
        self._connected = False
        self._authenticated = False

        # Reset state machine
        if self._state_machine:
            self._state_machine.reset()

    def reconnect(self) -> bool:
        """Reconnect to the server."""
        self.disconnect()
        time.sleep(0.5)
        return self.connect()

    def authenticate(self) -> bool:
        """Authenticate with the FTP server."""
        if not self._connected:
            if not self.connect():
                return False

        try:
            # Send USER command
            self._send(f"USER {self.config.username}\r\n".encode())
            response = self._recv()
            user_code = int(response[:3]) if response and len(response) >= 3 else 0

            # Update state for USER command
            if self._state_machine:
                self.update_state("USER", user_code)

            # Send PASS command
            self._send(f"PASS {self.config.password}\r\n".encode())
            response = self._recv()
            pass_code = int(response[:3]) if response and len(response) >= 3 else 0

            # Update state for PASS command
            if self._state_machine:
                self.update_state("PASS", pass_code)

            if response.startswith(b"230"):
                self._authenticated = True
                return True
            else:
                logging.warning(f"Authentication failed: {response}")
                return False

        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return False

    def _send(self, data: bytes):
        """Send data to the server."""
        if not self._socket:
            raise ConnectionError("Not connected")
        self._socket.sendall(data)

    def _recv(self, size: int = 4096) -> bytes:
        """Receive data from the server."""
        if not self._socket:
            raise ConnectionError("Not connected")
        try:
            return self._socket.recv(size)
        except socket.timeout:
            return b""

    def send_command(self, command: FTPCommand) -> FuzzResult:
        """Send a command and get the result. Updates state machine if enabled."""
        start_time = time.time()

        # Check if command is valid in current state (for logging/metrics)
        state_before = self.get_current_state()
        is_valid_in_state = True
        if self._state_machine and self.config.stateful_mode:
            is_valid_in_state = self._state_machine.can_execute(command.name)

        try:
            # Send the command
            self._send(command.to_bytes())

            # Get response
            response = self._recv()
            response_time = (time.time() - start_time) * 1000

            # Parse response code
            response_code = 0
            cve_triggered = None

            if response and len(response) >= 3:
                try:
                    response_code = int(response[:3])
                except ValueError:
                    pass

                # Check for CVE trigger in response (format: "599 CVE_TRIGGERED:CVE-XXXX-XXXX:message")
                response_str = response.decode('utf-8', errors='replace')
                if 'CVE_TRIGGERED:' in response_str:
                    try:
                        # Extract CVE ID from response
                        cve_start = response_str.find('CVE_TRIGGERED:') + len('CVE_TRIGGERED:')
                        cve_part = response_str[cve_start:]
                        cve_id = cve_part.split(':')[0].strip()
                        if cve_id.startswith('CVE-'):
                            cve_triggered = cve_id
                            logging.info(f"CVE DETECTED: {cve_id} triggered by {command.name}")
                    except Exception:
                        pass

            # Update state machine
            state_after = None
            if self._state_machine and self.config.stateful_mode:
                state_after = self.update_state(command.name, response_code)

            result = FuzzResult(
                iteration=self._current_iteration,
                command=command,
                response=response,
                response_code=response_code,
                success=True,
                response_time_ms=response_time,
                cve_triggered=cve_triggered,
            )

            # Log state transition
            if state_before and state_after:
                self.logger.logger.debug(
                    f"State: {state_before} --[{command.name}]--> {state_after.name} "
                    f"(valid: {is_valid_in_state}, code: {response_code})"
                )

            return result

        except socket.timeout:
            return FuzzResult(
                iteration=self._current_iteration,
                command=command,
                response=b"",
                success=False,
                error_message="Timeout",
                response_time_ms=(time.time() - start_time) * 1000,
            )

        except ConnectionError as e:
            return FuzzResult(
                iteration=self._current_iteration,
                command=command,
                response=b"",
                success=False,
                crashed=True,
                error_message=str(e),
                response_time_ms=(time.time() - start_time) * 1000,
            )

        except Exception as e:
            return FuzzResult(
                iteration=self._current_iteration,
                command=command,
                response=b"",
                success=False,
                error_message=str(e),
                response_time_ms=(time.time() - start_time) * 1000,
            )

    @abstractmethod
    def generate_seeds(self) -> List[FTPCommand]:
        """Generate seed inputs for fuzzing."""
        pass

    @abstractmethod
    def mutate(self, seed: FTPCommand) -> FTPCommand:
        """Mutate a seed input."""
        pass

    @abstractmethod
    def run(self, iterations: int = None) -> List[FuzzResult]:
        """Run the fuzzer for the specified number of iterations."""
        pass

    def _handle_crash(self, result: FuzzResult):
        """Handle a crash event."""
        self.logger.log_crash(
            result.iteration,
            result.command.name,
            result.command.to_bytes(),
            result.error_message
        )

        if self.config.reconnect_on_failure:
            for attempt in range(self.config.max_reconnect_attempts):
                time.sleep(1.0 * (attempt + 1))  # Exponential backoff
                if self.reconnect():
                    if self.authenticate():
                        logging.info("Reconnected and authenticated after crash")
                        return
            logging.error("Failed to reconnect after crash")

    def get_results(self) -> List[FuzzResult]:
        """Get all results from the current session."""
        return self._results.copy()

    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzer statistics including state coverage."""
        total = len(self._results)
        crashes = sum(1 for r in self._results if r.crashed)
        cves = set(r.cve_triggered for r in self._results if r.cve_triggered)

        stats = {
            "fuzzer_type": self.fuzzer_type.value,
            "session_id": self.session_id,
            "total_iterations": total,
            "crashes": crashes,
            "cves_triggered": list(cves),
            "success_rate": (total - crashes) / max(total, 1),
            "stateful_mode": self.config.stateful_mode,
        }

        # Add state coverage metrics if stateful mode enabled
        if self.config.stateful_mode and self._state_coverage:
            stats["state_coverage"] = self._state_coverage
            stats["states_visited"] = len([v for v in self._state_coverage.values() if v > 0])
            stats["unique_transitions"] = len(self._transition_coverage)
            stats["transition_coverage"] = self._transition_coverage

        return stats

    def generate_sequence(self) -> List[Tuple[str, str]]:
        """Generate a valid command sequence using state machine."""
        if self._sequence_generator:
            seq = self._sequence_generator.generate_valid_sequence(
                length=self.config.max_sequence_length
            )
            return seq.commands
        return []

    def execute_sequence(self, sequence: List[Tuple[str, str]]) -> List[FuzzResult]:
        """Execute a sequence of commands."""
        results = []
        for cmd_name, args in sequence:
            command = FTPCommand(name=cmd_name, args=args)
            result = self.send_command(command)
            results.append(result)
            self._results.append(result)

            if result.crashed:
                self._handle_crash(result)
                break

        return results
