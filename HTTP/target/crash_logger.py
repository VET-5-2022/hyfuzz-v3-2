"""
Crash Logger Module

Handles logging of crashes, CVE triggers, and fuzzing payloads for analysis.
"""

import os
import json
import threading
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
import hashlib


@dataclass
class CrashRecord:
    """Data class for crash records."""
    timestamp: str
    crash_type: str
    payload: str
    payload_hash: str
    request_method: str
    request_path: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    error_message: Optional[str]
    stack_trace: Optional[str]
    fuzzer_variant: Optional[str]
    iteration: Optional[int]


@dataclass
class CVETriggerRecord:
    """Data class for CVE trigger records."""
    timestamp: str
    cve_id: str
    cve_description: str
    trigger_payload: str
    payload_hash: str
    trigger_metadata: Dict[str, Any]
    request_method: str
    request_path: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    fuzzer_variant: Optional[str]
    iteration: Optional[int]


class CrashLogger:
    """
    Logger for recording crashes and CVE triggers during fuzzing.

    Provides thread-safe logging with deduplication based on payload hash.
    """

    def __init__(
        self,
        crash_log_dir: str = "logs/crashes",
        cve_log_dir: str = "logs/cve_triggers",
        deduplicate: bool = True
    ):
        """
        Initialize the crash logger.

        Args:
            crash_log_dir: Directory for crash logs
            cve_log_dir: Directory for CVE trigger logs
            deduplicate: Whether to deduplicate based on payload hash
        """
        self.crash_log_dir = crash_log_dir
        self.cve_log_dir = cve_log_dir
        self.deduplicate = deduplicate

        # Ensure directories exist
        os.makedirs(crash_log_dir, exist_ok=True)
        os.makedirs(cve_log_dir, exist_ok=True)

        # Thread lock for safe concurrent access
        self._lock = threading.Lock()

        # In-memory tracking for deduplication and statistics
        self._crash_hashes: set = set()
        self._cve_hashes: Dict[str, set] = {}  # cve_id -> set of hashes
        self._crash_count = 0
        self._cve_trigger_counts: Dict[str, int] = {}

        # Session identifier
        self._session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Load existing hashes for deduplication
        self._load_existing_hashes()

    def _load_existing_hashes(self):
        """Load existing payload hashes from log files for deduplication."""
        # Load crash hashes
        crash_summary_file = os.path.join(self.crash_log_dir, "crash_summary.json")
        if os.path.exists(crash_summary_file):
            try:
                with open(crash_summary_file, 'r') as f:
                    data = json.load(f)
                    self._crash_hashes = set(data.get('hashes', []))
            except (json.JSONDecodeError, IOError):
                pass

        # Load CVE trigger hashes
        cve_summary_file = os.path.join(self.cve_log_dir, "cve_summary.json")
        if os.path.exists(cve_summary_file):
            try:
                with open(cve_summary_file, 'r') as f:
                    data = json.load(f)
                    for cve_id, hashes in data.get('cve_hashes', {}).items():
                        self._cve_hashes[cve_id] = set(hashes)
            except (json.JSONDecodeError, IOError):
                pass

    def _compute_hash(self, payload: str) -> str:
        """Compute SHA256 hash of payload for deduplication."""
        return hashlib.sha256(payload.encode('utf-8', errors='replace')).hexdigest()[:16]

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        return datetime.now().isoformat()

    def log_crash(
        self,
        crash_type: str,
        payload: str,
        request_method: str,
        request_path: str,
        request_headers: Dict[str, str],
        request_body: Optional[str] = None,
        error_message: Optional[str] = None,
        stack_trace: Optional[str] = None,
        fuzzer_variant: Optional[str] = None,
        iteration: Optional[int] = None
    ) -> bool:
        """
        Log a crash event.

        Args:
            crash_type: Type of crash (e.g., "server_error", "timeout", "connection_reset")
            payload: The payload that caused the crash
            request_method: HTTP method
            request_path: Request path
            request_headers: Request headers
            request_body: Request body (if any)
            error_message: Error message (if any)
            stack_trace: Stack trace (if any)
            fuzzer_variant: Name of the fuzzer variant
            iteration: Fuzzing iteration number

        Returns:
            True if logged (not duplicate), False if duplicate
        """
        payload_hash = self._compute_hash(payload)

        with self._lock:
            # Check for duplicate
            if self.deduplicate and payload_hash in self._crash_hashes:
                return False

            self._crash_hashes.add(payload_hash)
            self._crash_count += 1

            record = CrashRecord(
                timestamp=self._get_timestamp(),
                crash_type=crash_type,
                payload=payload,
                payload_hash=payload_hash,
                request_method=request_method,
                request_path=request_path,
                request_headers=request_headers,
                request_body=request_body,
                error_message=error_message,
                stack_trace=stack_trace,
                fuzzer_variant=fuzzer_variant,
                iteration=iteration
            )

            # Write individual crash file
            crash_file = os.path.join(
                self.crash_log_dir,
                f"crash_{self._session_id}_{payload_hash}.json"
            )
            with open(crash_file, 'w') as f:
                json.dump(asdict(record), f, indent=2)

            # Update summary file
            self._update_crash_summary()

            return True

    def log_cve_trigger(
        self,
        cve_id: str,
        cve_description: str,
        trigger_payload: str,
        trigger_metadata: Dict[str, Any],
        request_method: str,
        request_path: str,
        request_headers: Dict[str, str],
        request_body: Optional[str] = None,
        fuzzer_variant: Optional[str] = None,
        iteration: Optional[int] = None
    ) -> bool:
        """
        Log a CVE trigger event.

        Args:
            cve_id: The CVE identifier
            cve_description: Description of the CVE
            trigger_payload: The payload that triggered the CVE
            trigger_metadata: Additional metadata about the trigger
            request_method: HTTP method
            request_path: Request path
            request_headers: Request headers
            request_body: Request body (if any)
            fuzzer_variant: Name of the fuzzer variant
            iteration: Fuzzing iteration number

        Returns:
            True if logged (not duplicate), False if duplicate
        """
        payload_hash = self._compute_hash(trigger_payload)

        with self._lock:
            # Initialize CVE hash set if needed
            if cve_id not in self._cve_hashes:
                self._cve_hashes[cve_id] = set()

            # Check for duplicate
            if self.deduplicate and payload_hash in self._cve_hashes[cve_id]:
                return False

            self._cve_hashes[cve_id].add(payload_hash)
            self._cve_trigger_counts[cve_id] = self._cve_trigger_counts.get(cve_id, 0) + 1

            record = CVETriggerRecord(
                timestamp=self._get_timestamp(),
                cve_id=cve_id,
                cve_description=cve_description,
                trigger_payload=trigger_payload,
                payload_hash=payload_hash,
                trigger_metadata=trigger_metadata,
                request_method=request_method,
                request_path=request_path,
                request_headers=request_headers,
                request_body=request_body,
                fuzzer_variant=fuzzer_variant,
                iteration=iteration
            )

            # Create CVE-specific directory
            cve_dir = os.path.join(self.cve_log_dir, cve_id)
            os.makedirs(cve_dir, exist_ok=True)

            # Write individual trigger file
            trigger_file = os.path.join(
                cve_dir,
                f"trigger_{self._session_id}_{payload_hash}.json"
            )
            with open(trigger_file, 'w') as f:
                json.dump(asdict(record), f, indent=2)

            # Update summary file
            self._update_cve_summary()

            return True

    def _update_crash_summary(self):
        """Update the crash summary file."""
        summary_file = os.path.join(self.crash_log_dir, "crash_summary.json")
        summary = {
            "total_crashes": self._crash_count,
            "unique_crashes": len(self._crash_hashes),
            "session_id": self._session_id,
            "last_updated": self._get_timestamp(),
            "hashes": list(self._crash_hashes)
        }
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

    def _update_cve_summary(self):
        """Update the CVE trigger summary file."""
        summary_file = os.path.join(self.cve_log_dir, "cve_summary.json")
        summary = {
            "total_triggers": sum(self._cve_trigger_counts.values()),
            "triggers_by_cve": self._cve_trigger_counts,
            "unique_payloads_by_cve": {
                cve_id: len(hashes)
                for cve_id, hashes in self._cve_hashes.items()
            },
            "session_id": self._session_id,
            "last_updated": self._get_timestamp(),
            "cve_hashes": {
                cve_id: list(hashes)
                for cve_id, hashes in self._cve_hashes.items()
            }
        }
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get logging statistics.

        Returns:
            Dictionary with crash and CVE trigger statistics
        """
        with self._lock:
            return {
                "crashes": {
                    "total": self._crash_count,
                    "unique": len(self._crash_hashes)
                },
                "cve_triggers": {
                    "total": sum(self._cve_trigger_counts.values()),
                    "by_cve": dict(self._cve_trigger_counts),
                    "unique_by_cve": {
                        cve_id: len(hashes)
                        for cve_id, hashes in self._cve_hashes.items()
                    }
                },
                "session_id": self._session_id
            }

    def get_all_crashes(self) -> List[Dict[str, Any]]:
        """
        Get all logged crashes.

        Returns:
            List of crash records
        """
        crashes = []
        for filename in os.listdir(self.crash_log_dir):
            if filename.startswith("crash_") and filename.endswith(".json"):
                filepath = os.path.join(self.crash_log_dir, filename)
                with open(filepath, 'r') as f:
                    crashes.append(json.load(f))
        return sorted(crashes, key=lambda x: x.get('timestamp', ''))

    def get_cve_triggers(self, cve_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get CVE trigger records.

        Args:
            cve_id: Optional CVE ID to filter by

        Returns:
            List of CVE trigger records
        """
        triggers = []

        if cve_id:
            cve_dir = os.path.join(self.cve_log_dir, cve_id)
            if os.path.exists(cve_dir):
                for filename in os.listdir(cve_dir):
                    if filename.endswith(".json"):
                        filepath = os.path.join(cve_dir, filename)
                        with open(filepath, 'r') as f:
                            triggers.append(json.load(f))
        else:
            for cve_id_dir in os.listdir(self.cve_log_dir):
                cve_dir = os.path.join(self.cve_log_dir, cve_id_dir)
                if os.path.isdir(cve_dir):
                    for filename in os.listdir(cve_dir):
                        if filename.endswith(".json"):
                            filepath = os.path.join(cve_dir, filename)
                            with open(filepath, 'r') as f:
                                triggers.append(json.load(f))

        return sorted(triggers, key=lambda x: x.get('timestamp', ''))

    def reset_session(self):
        """Start a new logging session."""
        with self._lock:
            self._session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Keep existing hashes for continued deduplication
