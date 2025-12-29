"""
Base Fuzzer Module

Provides the abstract base class for all fuzzer implementations.
"""

import time
import socket
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import threading

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.helpers import setup_logging, get_timestamp


@dataclass
class FuzzingResult:
    """Data class for fuzzing test results."""
    variant_name: str
    total_iterations: int
    crashes_found: int
    unique_crashes: int
    cve_triggers: Dict[str, int]
    unique_cve_triggers: Dict[str, int]
    total_cve_triggers: int
    start_time: str
    end_time: str
    duration_seconds: float
    requests_per_second: float
    seeds_generated: int
    mutations_performed: int
    coverage_metrics: Dict[str, Any] = field(default_factory=dict)
    error_count: int = 0
    timeout_count: int = 0

    # New metrics for ablation study
    time_to_first_crash: Optional[float] = None  # TTFC in seconds
    time_to_first_cve: Optional[float] = None    # Time to first CVE trigger
    execution_rate: float = 0.0                   # Iterations per second
    crash_rate: float = 0.0                       # Crashes per 1000 iterations
    cve_trigger_rate: float = 0.0                 # CVE triggers per 1000 iterations

    # Coverage metrics
    unique_paths_tested: int = 0
    unique_methods_tested: int = 0
    unique_status_codes: int = 0
    code_paths_covered: int = 0  # Simulated coverage based on CVE triggers


@dataclass
class FuzzingPayload:
    """Data class for a fuzzing payload."""
    method: str
    path: str
    headers: Dict[str, str]
    body: Optional[str] = None
    seed_id: Optional[str] = None
    mutation_id: Optional[str] = None
    generation_method: str = "unknown"


class BaseFuzzer(ABC):
    """
    Abstract base class for all fuzzer implementations.

    Provides common functionality for HTTP fuzzing including:
    - Connection management
    - Result tracking
    - Statistics collection
    """

    def __init__(
        self,
        target_host: str = "127.0.0.1",
        target_port: int = 8080,
        connection_timeout: float = 5.0,
        recv_timeout: float = 2.0,
        max_iterations: int = 1000,
        log_level: str = "INFO"
    ):
        """
        Initialize the base fuzzer.

        Args:
            target_host: Target server host
            target_port: Target server port
            connection_timeout: Connection timeout in seconds
            recv_timeout: Receive timeout in seconds
            max_iterations: Maximum fuzzing iterations
            log_level: Logging level
        """
        self.target_host = target_host
        self.target_port = target_port
        self.connection_timeout = connection_timeout
        self.recv_timeout = recv_timeout
        self.max_iterations = max_iterations

        # Set up logging
        self.logger = setup_logging(
            name=self.__class__.__name__,
            log_level=log_level
        )

        # Statistics tracking
        self._iteration_count = 0
        self._crash_count = 0
        self._cve_triggers: Dict[str, int] = {}
        self._unique_crashes: set = set()
        self._unique_cve_payloads: Dict[str, set] = {}
        self._seeds_generated = 0
        self._mutations_performed = 0
        self._error_count = 0
        self._timeout_count = 0

        # Timing
        self._start_time: Optional[datetime] = None
        self._end_time: Optional[datetime] = None

        # New metrics tracking
        self._time_to_first_crash: Optional[float] = None  # TTFC
        self._time_to_first_cve: Optional[float] = None
        self._first_crash_recorded = False
        self._first_cve_recorded = False

        # Coverage tracking (with size limits to prevent memory growth)
        self._unique_paths: set = set()
        self._unique_methods: set = set()
        self._unique_status_codes: set = set()
        # Use running average instead of storing all response times
        self._response_time_sum: float = 0.0
        self._response_time_count: int = 0

        # State
        self._running = False
        self._lock = threading.Lock()

        # Session for HTTP requests
        self._session: Optional[requests.Session] = None

    @property
    def variant_name(self) -> str:
        """Get the fuzzer variant name."""
        return self.__class__.__name__

    @abstractmethod
    def generate_seed(self) -> FuzzingPayload:
        """
        Generate a seed payload for fuzzing.

        Returns:
            FuzzingPayload instance
        """
        pass

    @abstractmethod
    def mutate(self, payload: FuzzingPayload) -> FuzzingPayload:
        """
        Mutate a payload.

        Args:
            payload: Original payload to mutate

        Returns:
            Mutated FuzzingPayload
        """
        pass

    def send_payload(self, payload: FuzzingPayload) -> Tuple[Optional[requests.Response], Optional[str]]:
        """
        Send a fuzzing payload to the target.

        Args:
            payload: The fuzzing payload to send

        Returns:
            Tuple of (response, error_message)
        """
        try:
            url = f"http://{self.target_host}:{self.target_port}{payload.path}"

            response = self._session.request(
                method=payload.method,
                url=url,
                headers=payload.headers,
                data=payload.body,
                timeout=(self.connection_timeout, self.recv_timeout),
                allow_redirects=False
            )

            return response, None

        except requests.exceptions.Timeout:
            self._timeout_count += 1
            return None, "timeout"
        except requests.exceptions.ConnectionError as e:
            self._error_count += 1
            return None, f"connection_error: {e}"
        except Exception as e:
            self._error_count += 1
            return None, f"error: {e}"

    def analyze_response(
        self,
        payload: FuzzingPayload,
        response: Optional[requests.Response],
        error: Optional[str]
    ) -> Dict[str, Any]:
        """
        Analyze the response from the target.

        Args:
            payload: The sent payload
            response: Response from server (if any)
            error: Error message (if any)

        Returns:
            Dictionary with analysis results
        """
        result = {
            "crash_detected": False,
            "cve_triggered": [],
            "status_code": None,
            "response_time": None,
            "error": error
        }

        # Track coverage metrics (with size limits)
        if len(self._unique_paths) < 1000:  # Limit to prevent memory growth
            self._unique_paths.add(payload.path.split('?')[0])  # Path without query
        self._unique_methods.add(payload.method)

        if error:
            if "connection_error" in error or "timeout" in error:
                result["crash_detected"] = True
                self._crash_count += 1

                # Record TTFC (Time To First Crash)
                if not self._first_crash_recorded and self._start_time:
                    self._time_to_first_crash = (datetime.now() - self._start_time).total_seconds()
                    self._first_crash_recorded = True

            return result

        if response is not None:
            result["status_code"] = response.status_code
            result["response_time"] = response.elapsed.total_seconds()

            # Track coverage
            self._unique_status_codes.add(response.status_code)
            # Running average for response times (no memory growth)
            self._response_time_sum += result["response_time"]
            self._response_time_count += 1

            # Check for crash indicators
            crash_header = response.headers.get("X-Crash-Type")
            if crash_header:
                result["crash_detected"] = True
                self._crash_count += 1

                # Record TTFC
                if not self._first_crash_recorded and self._start_time:
                    self._time_to_first_crash = (datetime.now() - self._start_time).total_seconds()
                    self._first_crash_recorded = True

            # Check response body for CVE triggers
            try:
                body = response.json()
                # Check for both "vulnerable" and "crashed" status (crashed may also contain CVE info)
                if body.get("status") in ["vulnerable", "crashed"]:
                    for cve_info in body.get("triggered_cves", []):
                        cve_id = cve_info.get("cve_id")
                        if cve_id:
                            result["cve_triggered"].append(cve_id)
                            self._cve_triggers[cve_id] = self._cve_triggers.get(cve_id, 0) + 1

                            # Record Time To First CVE
                            if not self._first_cve_recorded and self._start_time:
                                self._time_to_first_cve = (datetime.now() - self._start_time).total_seconds()
                                self._first_cve_recorded = True

                            # Track unique payloads per CVE
                            if cve_id not in self._unique_cve_payloads:
                                self._unique_cve_payloads[cve_id] = set()
                            payload_str = f"{payload.method}|{payload.path}|{payload.headers}|{payload.body}"
                            self._unique_cve_payloads[cve_id].add(hash(payload_str))
            except Exception:
                pass

            # 5xx errors indicate potential crashes
            if response.status_code >= 500:
                result["crash_detected"] = True

                # Record TTFC for 5xx errors too
                if not self._first_crash_recorded and self._start_time:
                    self._time_to_first_crash = (datetime.now() - self._start_time).total_seconds()
                    self._first_crash_recorded = True

        return result

    def run(self, iterations: Optional[int] = None) -> FuzzingResult:
        """
        Run the fuzzing session.

        Args:
            iterations: Number of iterations (defaults to max_iterations)

        Returns:
            FuzzingResult with statistics
        """
        if iterations is None:
            iterations = self.max_iterations

        self._running = True
        self._start_time = datetime.now()
        self._session = requests.Session()

        self.logger.info(f"Starting {self.variant_name} fuzzing session with {iterations} iterations")

        # Track timing for progress display
        last_progress_time = time.time()
        progress_interval = 30  # Show progress every 30 seconds minimum

        try:
            for i in range(iterations):
                if not self._running:
                    break

                self._iteration_count = i + 1

                # Generate or get seed
                seed = self.generate_seed()
                self._seeds_generated += 1

                # Mutate the seed
                payload = self.mutate(seed)
                self._mutations_performed += 1

                # Send payload and analyze response
                response, error = self.send_payload(payload)
                result = self.analyze_response(payload, response, error)

                # Log progress more frequently - every 10 iterations OR every 30 seconds
                current_time = time.time()
                time_since_last = current_time - last_progress_time

                if (i + 1) % 10 == 0 or time_since_last >= progress_interval:
                    elapsed = (datetime.now() - self._start_time).total_seconds()
                    rate = (i + 1) / elapsed if elapsed > 0 else 0
                    self.logger.info(
                        f"[{i + 1}/{iterations}] "
                        f"crashes={self._crash_count}, "
                        f"CVEs={sum(self._cve_triggers.values())}, "
                        f"rate={rate:.2f}/s, "
                        f"elapsed={elapsed:.0f}s"
                    )
                    last_progress_time = current_time

                # Small delay to avoid overwhelming the target
                time.sleep(0.01)

        except KeyboardInterrupt:
            self.logger.info("Fuzzing interrupted by user")
        finally:
            self._running = False
            self._end_time = datetime.now()
            if self._session:
                self._session.close()

        return self._generate_result()

    def _generate_result(self) -> FuzzingResult:
        """Generate the final fuzzing result."""
        duration = 0.0
        if self._start_time and self._end_time:
            duration = (self._end_time - self._start_time).total_seconds()

        rps = self._iteration_count / duration if duration > 0 else 0

        # Calculate rates per 1000 iterations
        crash_rate = (self._crash_count / self._iteration_count * 1000) if self._iteration_count > 0 else 0
        cve_rate = (sum(self._cve_triggers.values()) / self._iteration_count * 1000) if self._iteration_count > 0 else 0

        # Calculate coverage score based on unique CVEs triggered
        # Each unique CVE represents a code path discovered
        code_paths = len(self._cve_triggers)

        return FuzzingResult(
            variant_name=self.variant_name,
            total_iterations=self._iteration_count,
            crashes_found=self._crash_count,
            unique_crashes=len(self._unique_crashes),
            cve_triggers=dict(self._cve_triggers),
            unique_cve_triggers={
                cve_id: len(payloads)
                for cve_id, payloads in self._unique_cve_payloads.items()
            },
            total_cve_triggers=sum(self._cve_triggers.values()),
            start_time=self._start_time.isoformat() if self._start_time else "",
            end_time=self._end_time.isoformat() if self._end_time else "",
            duration_seconds=duration,
            requests_per_second=rps,
            seeds_generated=self._seeds_generated,
            mutations_performed=self._mutations_performed,
            error_count=self._error_count,
            timeout_count=self._timeout_count,
            # New metrics
            time_to_first_crash=self._time_to_first_crash,
            time_to_first_cve=self._time_to_first_cve,
            execution_rate=rps,
            crash_rate=crash_rate,
            cve_trigger_rate=cve_rate,
            unique_paths_tested=len(self._unique_paths),
            unique_methods_tested=len(self._unique_methods),
            unique_status_codes=len(self._unique_status_codes),
            code_paths_covered=code_paths
        )

    def stop(self):
        """Stop the fuzzing session."""
        self._running = False

    def reset_stats(self):
        """Reset all statistics."""
        with self._lock:
            self._iteration_count = 0
            self._crash_count = 0
            self._cve_triggers.clear()
            self._unique_crashes.clear()
            self._unique_cve_payloads.clear()
            self._seeds_generated = 0
            self._mutations_performed = 0
            self._error_count = 0
            self._timeout_count = 0
            self._start_time = None
            self._end_time = None
            # Reset new metrics
            self._time_to_first_crash = None
            self._time_to_first_cve = None
            self._first_crash_recorded = False
            self._first_cve_recorded = False
            self._unique_paths.clear()
            self._unique_methods.clear()
            self._unique_status_codes.clear()
            self._response_time_sum = 0.0
            self._response_time_count = 0

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics."""
        return {
            "iterations": self._iteration_count,
            "crashes": self._crash_count,
            "cve_triggers": dict(self._cve_triggers),
            "seeds_generated": self._seeds_generated,
            "mutations_performed": self._mutations_performed,
            "errors": self._error_count,
            "timeouts": self._timeout_count
        }
