"""
Crash Logger for recording fuzzing-induced crashes and CVE triggers.
Records payload, timestamp, CVE information, and crash context.
"""
import json
import os
import hashlib
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from pathlib import Path
import threading
from enum import Enum


class CrashType(Enum):
    """Types of crashes that can be recorded."""
    CVE_TRIGGER = "cve_trigger"
    SEGFAULT = "segfault"
    TIMEOUT = "timeout"
    CONNECTION_RESET = "connection_reset"
    PROTOCOL_ERROR = "protocol_error"
    UNKNOWN = "unknown"


@dataclass
class CrashRecord:
    """Record of a single crash event."""
    crash_id: str
    timestamp: str
    crash_type: str
    payload: str  # Base64 encoded if binary
    payload_hex: str
    payload_size: int
    command: str
    arguments: str
    cve_id: Optional[str] = None
    cve_name: Optional[str] = None
    error_message: str = ""
    stack_trace: str = ""
    server_state: Dict[str, Any] = field(default_factory=dict)
    fuzzer_type: str = ""
    iteration: int = 0
    session_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CrashRecord":
        """Create from dictionary."""
        return cls(**data)


class CrashLogger:
    """Logger for recording and managing crash records."""

    def __init__(self, log_dir: str = "./results/crashes"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.crashes: List[CrashRecord] = []
        self.cve_triggers: Dict[str, List[CrashRecord]] = {}
        self._lock = threading.Lock()

        # Log file paths
        self.crash_log_file = self.log_dir / "crashes.json"
        self.cve_log_file = self.log_dir / "cve_triggers.json"
        self.summary_file = self.log_dir / "summary.json"

        # Load existing logs if present
        self._load_existing_logs()

    def _load_existing_logs(self):
        """Load existing crash logs from disk."""
        if self.crash_log_file.exists():
            try:
                with open(self.crash_log_file, 'r') as f:
                    data = json.load(f)
                    self.crashes = [CrashRecord.from_dict(c) for c in data]
            except (json.JSONDecodeError, KeyError):
                self.crashes = []

        if self.cve_log_file.exists():
            try:
                with open(self.cve_log_file, 'r') as f:
                    data = json.load(f)
                    for cve_id, records in data.items():
                        self.cve_triggers[cve_id] = [CrashRecord.from_dict(r) for r in records]
            except (json.JSONDecodeError, KeyError):
                self.cve_triggers = {}

    def _generate_crash_id(self, payload: bytes, command: str) -> str:
        """Generate a unique crash ID based on payload hash."""
        content = command.encode() + payload
        return hashlib.sha256(content).hexdigest()[:16]

    def _encode_payload(self, payload: bytes) -> tuple:
        """Encode payload for storage."""
        import base64

        # Try to decode as string, otherwise base64 encode
        try:
            payload_str = payload.decode('utf-8', errors='replace')
        except:
            payload_str = base64.b64encode(payload).decode('ascii')

        payload_hex = payload.hex()

        return payload_str, payload_hex

    def log_crash(
        self,
        payload: bytes,
        command: str,
        arguments: str = "",
        crash_type: CrashType = CrashType.UNKNOWN,
        cve_id: Optional[str] = None,
        cve_name: Optional[str] = None,
        error_message: str = "",
        stack_trace: str = "",
        server_state: Optional[Dict[str, Any]] = None,
        fuzzer_type: str = "",
        iteration: int = 0,
        session_id: str = "",
    ) -> CrashRecord:
        """Log a crash event."""
        with self._lock:
            crash_id = self._generate_crash_id(payload, command)
            payload_str, payload_hex = self._encode_payload(payload)

            record = CrashRecord(
                crash_id=crash_id,
                timestamp=datetime.now().isoformat(),
                crash_type=crash_type.value,
                payload=payload_str,
                payload_hex=payload_hex,
                payload_size=len(payload),
                command=command,
                arguments=arguments,
                cve_id=cve_id,
                cve_name=cve_name,
                error_message=error_message,
                stack_trace=stack_trace,
                server_state=server_state or {},
                fuzzer_type=fuzzer_type,
                iteration=iteration,
                session_id=session_id,
            )

            self.crashes.append(record)

            # Track CVE-specific triggers
            if cve_id:
                if cve_id not in self.cve_triggers:
                    self.cve_triggers[cve_id] = []
                self.cve_triggers[cve_id].append(record)

            # Save individual crash file
            self._save_crash_file(record)

            # Update main log files
            self._save_logs()

            return record

    def _save_crash_file(self, record: CrashRecord):
        """Save individual crash to a separate file."""
        crash_file = self.log_dir / f"crash_{record.crash_id}.json"
        with open(crash_file, 'w') as f:
            json.dump(record.to_dict(), f, indent=2)

        # Also save raw payload
        payload_file = self.log_dir / f"payload_{record.crash_id}.bin"
        with open(payload_file, 'wb') as f:
            f.write(bytes.fromhex(record.payload_hex))

    def _save_logs(self):
        """Save all logs to disk."""
        # Save crashes
        with open(self.crash_log_file, 'w') as f:
            json.dump([c.to_dict() for c in self.crashes], f, indent=2)

        # Save CVE triggers
        cve_data = {}
        for cve_id, records in self.cve_triggers.items():
            cve_data[cve_id] = [r.to_dict() for r in records]
        with open(self.cve_log_file, 'w') as f:
            json.dump(cve_data, f, indent=2)

        # Save summary
        self._save_summary()

    def _save_summary(self):
        """Save crash summary statistics."""
        summary = {
            "total_crashes": len(self.crashes),
            "unique_cves_triggered": len(self.cve_triggers),
            "cve_trigger_counts": {cve: len(records) for cve, records in self.cve_triggers.items()},
            "crash_type_counts": {},
            "first_crash": self.crashes[0].timestamp if self.crashes else None,
            "last_crash": self.crashes[-1].timestamp if self.crashes else None,
            "crashes_by_fuzzer": {},
        }

        # Count crash types
        for crash in self.crashes:
            crash_type = crash.crash_type
            summary["crash_type_counts"][crash_type] = summary["crash_type_counts"].get(crash_type, 0) + 1

            fuzzer = crash.fuzzer_type or "unknown"
            if fuzzer not in summary["crashes_by_fuzzer"]:
                summary["crashes_by_fuzzer"][fuzzer] = {"total": 0, "cves": set()}
            summary["crashes_by_fuzzer"][fuzzer]["total"] += 1
            if crash.cve_id:
                summary["crashes_by_fuzzer"][fuzzer]["cves"].add(crash.cve_id)

        # Convert sets to lists for JSON serialization
        for fuzzer in summary["crashes_by_fuzzer"]:
            summary["crashes_by_fuzzer"][fuzzer]["cves"] = list(
                summary["crashes_by_fuzzer"][fuzzer]["cves"]
            )

        with open(self.summary_file, 'w') as f:
            json.dump(summary, f, indent=2)

    def get_crashes_by_cve(self, cve_id: str) -> List[CrashRecord]:
        """Get all crashes for a specific CVE."""
        return self.cve_triggers.get(cve_id, [])

    def get_crashes_by_fuzzer(self, fuzzer_type: str) -> List[CrashRecord]:
        """Get all crashes from a specific fuzzer type."""
        return [c for c in self.crashes if c.fuzzer_type == fuzzer_type]

    def get_unique_payloads(self) -> List[bytes]:
        """Get all unique crash payloads."""
        seen = set()
        unique = []
        for crash in self.crashes:
            if crash.payload_hex not in seen:
                seen.add(crash.payload_hex)
                unique.append(bytes.fromhex(crash.payload_hex))
        return unique

    def get_statistics(self) -> Dict[str, Any]:
        """Get crash statistics."""
        stats = {
            "total_crashes": len(self.crashes),
            "unique_cves": list(self.cve_triggers.keys()),
            "cve_counts": {cve: len(records) for cve, records in self.cve_triggers.items()},
            "crash_types": {},
            "avg_payload_size": 0,
            "crashes_by_command": {},
        }

        if self.crashes:
            stats["avg_payload_size"] = sum(c.payload_size for c in self.crashes) / len(self.crashes)

            for crash in self.crashes:
                stats["crash_types"][crash.crash_type] = stats["crash_types"].get(crash.crash_type, 0) + 1
                stats["crashes_by_command"][crash.command] = stats["crashes_by_command"].get(crash.command, 0) + 1

        return stats

    def export_for_comparison(self, output_file: str = None) -> Dict[str, Any]:
        """Export crash data in a format suitable for comparison across fuzzer types."""
        output_file = output_file or str(self.log_dir / "comparison_data.json")

        comparison_data = {
            "generated_at": datetime.now().isoformat(),
            "fuzzers": {},
        }

        # Group by fuzzer type
        for crash in self.crashes:
            fuzzer = crash.fuzzer_type or "unknown"
            if fuzzer not in comparison_data["fuzzers"]:
                comparison_data["fuzzers"][fuzzer] = {
                    "total_crashes": 0,
                    "unique_cves": set(),
                    "crash_types": {},
                    "first_crash_time": None,
                    "crashes": [],
                }

            fuzzer_data = comparison_data["fuzzers"][fuzzer]
            fuzzer_data["total_crashes"] += 1

            if crash.cve_id:
                fuzzer_data["unique_cves"].add(crash.cve_id)

            fuzzer_data["crash_types"][crash.crash_type] = fuzzer_data["crash_types"].get(crash.crash_type, 0) + 1

            if fuzzer_data["first_crash_time"] is None:
                fuzzer_data["first_crash_time"] = crash.timestamp

            fuzzer_data["crashes"].append({
                "crash_id": crash.crash_id,
                "timestamp": crash.timestamp,
                "cve_id": crash.cve_id,
                "command": crash.command,
                "iteration": crash.iteration,
            })

        # Convert sets to lists for JSON
        for fuzzer in comparison_data["fuzzers"]:
            comparison_data["fuzzers"][fuzzer]["unique_cves"] = list(
                comparison_data["fuzzers"][fuzzer]["unique_cves"]
            )

        with open(output_file, 'w') as f:
            json.dump(comparison_data, f, indent=2)

        return comparison_data

    def clear(self):
        """Clear all crash records."""
        with self._lock:
            self.crashes = []
            self.cve_triggers = {}
            self._save_logs()
