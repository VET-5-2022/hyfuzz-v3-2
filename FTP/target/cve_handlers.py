"""
CVE vulnerability handlers for the FTP server.
This module simulates 10 known CVE vulnerabilities in FTP implementations.
Supports state-aware CVE triggering based on FTP protocol state.
"""
import re
import os
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any, Tuple, Set
from enum import Enum


class CVESeverity(Enum):
    """CVE severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FTPProtocolState(Enum):
    """FTP protocol states for state-aware CVE checking."""
    ANY = "any"                      # Vulnerable in any state
    CONNECTED = "connected"          # After TCP connection
    USER_SENT = "user_sent"          # After USER command
    AUTHENTICATED = "authenticated"  # After successful login
    PASSIVE_MODE = "passive_mode"    # After PASV command
    ACTIVE_MODE = "active_mode"      # After PORT command
    TRANSFER_READY = "transfer_ready"  # Ready for data transfer
    RENAMING = "renaming"            # After RNFR command


@dataclass
class CVEInfo:
    """Information about a CVE vulnerability."""
    cve_id: str
    name: str
    description: str
    severity: CVESeverity
    affected_command: str
    trigger_pattern: str
    cvss_score: float
    # State-aware fields
    required_states: Set[FTPProtocolState] = field(default_factory=lambda: {FTPProtocolState.ANY})
    requires_authentication: bool = True
    requires_data_mode: bool = False  # Requires PASV/PORT first


@dataclass
class CVETriggerResult:
    """Result of a CVE trigger check."""
    triggered: bool
    cve_id: str
    payload: bytes
    timestamp: datetime = field(default_factory=datetime.now)
    should_crash: bool = False
    error_message: str = ""
    state_at_trigger: Optional[str] = None  # Protocol state when triggered
    state_violation: bool = False  # True if triggered despite wrong state


class CVEHandler(ABC):
    """Abstract base class for CVE vulnerability handlers."""

    def __init__(self, cve_info: CVEInfo):
        self.cve_info = cve_info
        self.trigger_count = 0
        self.last_triggered: Optional[datetime] = None
        self._triggers_by_state: Dict[str, int] = {}

    def is_valid_state(self, current_state: Optional[str]) -> bool:
        """Check if CVE can be triggered in current state."""
        if FTPProtocolState.ANY in self.cve_info.required_states:
            return True
        if current_state is None:
            return True  # No state tracking, allow trigger

        # Check if current state matches any required state
        for required in self.cve_info.required_states:
            if required.value.upper() == current_state.upper():
                return True
        return False

    @abstractmethod
    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check if the vulnerability is triggered by the given input."""
        pass

    def record_trigger(self, result: CVETriggerResult):
        """Record a successful trigger."""
        if result.triggered:
            self.trigger_count += 1
            self.last_triggered = result.timestamp
            # Track by state
            state = result.state_at_trigger or "unknown"
            self._triggers_by_state[state] = self._triggers_by_state.get(state, 0) + 1

    def get_state_statistics(self) -> Dict[str, Any]:
        """Get statistics about triggers by state."""
        return {
            "total_triggers": self.trigger_count,
            "triggers_by_state": self._triggers_by_state,
            "required_states": [s.value for s in self.cve_info.required_states],
        }


class CVE_2024_46483_Handler(CVEHandler):
    """
    CVE-2024-46483: Xlight FTP Server Pre-Auth Heap Overflow.
    Integer overflow in SFTP packet parsing leads to heap overflow.
    CVSS 9.8 CRITICAL - Pre-authentication vulnerability.
    Reference: https://github.com/kn32/cve-2024-46483
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2024-46483",
            name="Xlight FTP Pre-Auth Heap Overflow",
            description="Integer overflow in SFTP packet parsing leads to heap overflow with attacker-controlled content",
            severity=CVESeverity.CRITICAL,
            affected_command="*",
            trigger_pattern=r".*\xff{4,}.*",
            cvss_score=9.8,
            required_states={FTPProtocolState.ANY},  # Pre-auth vulnerability
            requires_authentication=False
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for heap overflow trigger via malformed length fields."""
        triggered = False
        should_crash = False

        full_data = (command + " " + args).encode() + (data or b"")

        # Check for patterns that simulate integer overflow in length parsing
        # The vulnerability involves 4-byte length fields that overflow
        if len(full_data) > 512:
            # Simulate large memmove trigger
            if b'\xff\xff\xff' in full_data or b'\x00\x00\x00\x00' in full_data:
                triggered = True
                # Crash on specific overflow patterns (simulating ~4GB memmove)
                if full_data.count(b'\xff') > 20 or len(full_data) > 2000:
                    should_crash = True

        # Also trigger on very long strings (simulating string length overflow)
        if len(args) > 1024:
            triggered = True
            if len(args) > 4096:
                should_crash = True

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=full_data,
            should_crash=should_crash,
            error_message="Heap overflow via integer overflow in packet parsing" if triggered else "",
            state_at_trigger=current_state
        )


class CVE_2019_12815_Handler(CVEHandler):
    """
    CVE-2019-12815: ProFTPD mod_copy vulnerability.
    Allows arbitrary file copy by unauthenticated users.
    Note: Can be triggered without authentication (vulnerability!)
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2019-12815",
            name="ProFTPD mod_copy Arbitrary File Copy",
            description="Unauthenticated arbitrary file copy via SITE CPFR/CPTO commands",
            severity=CVESeverity.CRITICAL,
            affected_command="SITE",
            trigger_pattern=r"SITE\s+(CPFR|CPTO)\s+/",
            cvss_score=9.8,
            required_states={FTPProtocolState.ANY},  # Works even without auth!
            requires_authentication=False  # This is the vulnerability!
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for mod_copy exploitation attempt."""
        triggered = False
        should_crash = False

        if command.upper() == "SITE":
            args_upper = args.upper()
            # Check for CPFR/CPTO with path traversal
            if "CPFR" in args_upper or "CPTO" in args_upper:
                if "../" in args or "/etc/" in args or "/root/" in args:
                    triggered = True
                    # Crash on specific sensitive paths
                    if "/etc/shadow" in args or "/etc/passwd" in args:
                        should_crash = True

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=args.encode() if args else b"",
            should_crash=should_crash,
            error_message="Arbitrary file copy attempt detected" if triggered else "",
            state_at_trigger=current_state
        )


class CVE_2015_3306_Handler(CVEHandler):
    """
    CVE-2015-3306: ProFTPD mod_copy arbitrary file read.
    Allows reading arbitrary files on the server.
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2015-3306",
            name="ProFTPD mod_copy Arbitrary File Read",
            description="Arbitrary file read via mod_copy module",
            severity=CVESeverity.HIGH,
            affected_command="SITE",
            trigger_pattern=r"SITE\s+CPFR\s+/",
            cvss_score=7.5,
            required_states={FTPProtocolState.AUTHENTICATED},
            requires_authentication=True
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for arbitrary file read attempt."""
        triggered = False
        should_crash = False

        if command.upper() == "SITE" and "CPFR" in args.upper():
            # Check for attempts to read sensitive files
            sensitive_patterns = ["/proc/", "/sys/", "/dev/", "/.ssh/", "/.gnupg/"]
            for pattern in sensitive_patterns:
                if pattern in args:
                    triggered = True
                    break

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=args.encode() if args else b"",
            should_crash=should_crash,
            error_message="Sensitive file read attempt" if triggered else "",
            state_at_trigger=current_state
        )


class CVE_2010_4221_Handler(CVEHandler):
    """
    CVE-2010-4221: ProFTPD telnet IAC buffer overflow.
    Stack-based buffer overflow via telnet IAC escape sequences.
    Can be triggered in any state (pre-auth vulnerability!)
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2010-4221",
            name="ProFTPD Telnet IAC Buffer Overflow",
            description="Stack-based buffer overflow in telnet IAC handling",
            severity=CVESeverity.CRITICAL,
            affected_command="*",
            trigger_pattern=r"\xff[\xf0-\xff]",
            cvss_score=10.0,
            required_states={FTPProtocolState.ANY},  # Pre-auth vulnerability
            requires_authentication=False
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for telnet IAC overflow attempt."""
        triggered = False
        should_crash = False

        # Check for telnet IAC sequences
        full_data = (command + " " + args).encode() + (data or b"")

        # IAC sequences: 0xFF followed by command byte
        iac_count = full_data.count(b'\xff')
        if iac_count > 10:
            triggered = True
            # Crash on long IAC sequences
            if iac_count > 100:
                should_crash = True

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=full_data,
            should_crash=should_crash,
            error_message="Telnet IAC buffer overflow detected" if triggered else "",
            state_at_trigger=current_state
        )


class CVE_2024_4040_Handler(CVEHandler):
    """
    CVE-2024-4040: CrushFTP Server-Side Template Injection (SSTI).
    Allows unauthenticated arbitrary file read and RCE.
    CVSS 9.8 CRITICAL - Actively exploited in the wild.
    Reference: https://attackerkb.com/topics/20oYjlmfXa/cve-2024-4040
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2024-4040",
            name="CrushFTP SSTI/RCE",
            description="Server-side template injection allowing arbitrary file read and remote code execution",
            severity=CVESeverity.CRITICAL,
            affected_command="*",
            trigger_pattern=r".*\{.*\}.*|.*\$\{.*\}.*",
            cvss_score=9.8,
            required_states={FTPProtocolState.ANY},
            requires_authentication=False  # Unauthenticated exploitation!
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for SSTI exploitation patterns."""
        triggered = False
        should_crash = False

        # Check for template injection patterns
        ssti_patterns = [
            "${", "#{", "{{", "}}", "%{",
            "<INCLUDE>", "sessions.obj",
            "..%2f", "../", "..\\",
            "AS_ADMIN", "command=zip"
        ]

        full_input = command + " " + args
        full_input_lower = full_input.lower()

        for pattern in ssti_patterns:
            if pattern.lower() in full_input_lower:
                triggered = True
                break

        # Check for file path access patterns (VFS escape)
        sensitive_paths = ["/etc/", "/root/", "/home/", "sessions.obj", "users.xml"]
        for path in sensitive_paths:
            if path in args:
                triggered = True
                should_crash = True
                break

        # Template variable exploitation
        if re.search(r'\$\{[^}]+\}', args) or re.search(r'\{\{[^}]+\}\}', args):
            triggered = True
            should_crash = True

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=args.encode() if args else b"",
            should_crash=should_crash,
            error_message="Template injection detected - potential RCE" if triggered else "",
            state_at_trigger=current_state
        )


class CVE_2019_18217_Handler(CVEHandler):
    """
    CVE-2019-18217: ProFTPD CWD command crash.
    Crash due to invalid memory access in CWD handling.
    Requires: Authentication
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2019-18217",
            name="ProFTPD CWD Command Crash",
            description="Invalid memory access in CWD command handling",
            severity=CVESeverity.MEDIUM,
            affected_command="CWD",
            trigger_pattern=r"CWD\s+\.\./\.\./\.\./",
            cvss_score=7.5,
            required_states={FTPProtocolState.AUTHENTICATED, FTPProtocolState.PASSIVE_MODE, FTPProtocolState.ACTIVE_MODE},
            requires_authentication=True
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for CWD crash trigger."""
        triggered = False
        should_crash = False

        if command.upper() == "CWD":
            # Check for deep path traversal
            traversal_count = args.count("../")
            if traversal_count > 10:
                triggered = True
                if traversal_count > 50:
                    should_crash = True

            # Check for very long path
            if len(args) > 4096:
                triggered = True
                should_crash = True

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=args.encode() if args else b"",
            should_crash=should_crash,
            error_message="CWD path traversal attack detected" if triggered else "",
            state_at_trigger=current_state
        )


class CVE_2024_48651_Handler(CVEHandler):
    """
    CVE-2024-48651: ProFTPD mod_sql GID 0 Privilege Escalation.
    Supplemental group inheritance grants unintended access to GID 0.
    CVSS 7.5 HIGH - Published November 2024.
    Reference: https://vigilance.fr/vulnerability/ProFTPD-privilege-escalation-via-group-inheritance-45778
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2024-48651",
            name="ProFTPD mod_sql Privilege Escalation",
            description="Supplemental group inheritance grants unintended access to GID 0",
            severity=CVESeverity.HIGH,
            affected_command="*",
            trigger_pattern=r"(USER|PASS|SITE)\s+.*",
            cvss_score=7.5,
            required_states={FTPProtocolState.ANY},
            requires_authentication=False
        ))
        self._sql_injection_attempts = 0

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for privilege escalation via SQL injection in mod_sql."""
        triggered = False
        should_crash = False

        # SQL injection patterns that could exploit mod_sql
        sql_patterns = [
            "' OR '1'='1", "'; --", "' UNION SELECT",
            "admin'--", "root'--", "1=1", "OR 1=1",
            "' OR ''='", "\"; DROP", "/**/",
            "GRANT ALL", "GID=0", "GROUP BY"
        ]

        full_input = (command + " " + args).lower()

        for pattern in sql_patterns:
            if pattern.lower() in full_input:
                self._sql_injection_attempts += 1
                triggered = True
                break

        # Trigger on privilege escalation attempts
        if command.upper() == "USER":
            # Check for admin/root username with SQL injection
            if any(p in args.lower() for p in ["admin", "root", "wheel", "sudo"]):
                if any(c in args for c in ["'", '"', ";", "--", "/*"]):
                    triggered = True
                    should_crash = True

        # Multiple SQL attempts suggest exploitation
        if self._sql_injection_attempts > 5:
            should_crash = True

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=(command + " " + args).encode(),
            should_crash=should_crash,
            error_message="SQL injection for privilege escalation detected" if triggered else "",
            state_at_trigger=current_state
        )


class CVE_2023_51713_Handler(CVEHandler):
    """
    CVE-2023-51713: ProFTPD Out-of-Bounds Read DoS.
    One-byte out-of-bounds read in make_ftp_cmd due to quote/backslash mishandling.
    CVSS 7.5 HIGH - Can cause daemon crash.
    Reference: https://cvedetails.com/cve/CVE-2023-51713
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2023-51713",
            name="ProFTPD OOB Read DoS",
            description="One-byte out-of-bounds read in make_ftp_cmd causing daemon crash",
            severity=CVESeverity.HIGH,
            affected_command="*",
            trigger_pattern=r".*[\\'\"].*",
            cvss_score=7.5,
            required_states={FTPProtocolState.ANY},
            requires_authentication=False
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for OOB read via quote/backslash mishandling."""
        triggered = False
        should_crash = False

        full_input = command + " " + args

        # Check for quote/backslash patterns that trigger the vulnerability
        # The bug is in handling of escaped quotes at command boundaries
        problematic_patterns = [
            r'\\$',           # Trailing backslash
            r'\"$',           # Trailing escaped quote
            r"\'$",           # Trailing escaped single quote
            r'\\\\+',         # Multiple backslashes
            r'["\']\\',       # Quote followed by backslash
        ]

        for pattern in problematic_patterns:
            if re.search(pattern, full_input):
                triggered = True
                break

        # Count unbalanced quotes (indicates potential OOB)
        single_quotes = full_input.count("'")
        double_quotes = full_input.count('"')
        backslashes = full_input.count("\\")

        if single_quotes % 2 != 0 or double_quotes % 2 != 0:
            triggered = True

        # Many backslashes near quotes trigger crash
        if backslashes > 5:
            triggered = True
            if backslashes > 20:
                should_crash = True

        # Specific crash pattern: backslash at end of command
        if full_input.rstrip().endswith("\\"):
            triggered = True
            should_crash = True

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=full_input.encode(),
            should_crash=should_crash,
            error_message="OOB read via quote/backslash mishandling" if triggered else "",
            state_at_trigger=current_state
        )


class CVE_2022_34977_Handler(CVEHandler):
    """
    CVE-2022-34977: PureFTPd buffer overflow.
    Buffer overflow in domlsd function.
    Requires: PASV/PORT mode for MLSD to work
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2022-34977",
            name="PureFTPd Buffer Overflow",
            description="Buffer overflow in MLSD command handling",
            severity=CVESeverity.CRITICAL,
            affected_command="MLSD",
            trigger_pattern=r"MLSD\s+.{1000,}",
            cvss_score=9.8,
            required_states={FTPProtocolState.PASSIVE_MODE, FTPProtocolState.ACTIVE_MODE},
            requires_authentication=True,
            requires_data_mode=True
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for MLSD buffer overflow trigger."""
        triggered = False
        should_crash = False
        state_violation = not self.is_valid_state(current_state)

        if command.upper() == "MLSD":
            # Check for long argument
            if len(args) > 500:
                triggered = True
                if len(args) > 2000:
                    should_crash = True

            # Check for specific overflow patterns
            if "A" * 100 in args or "%" * 50 in args:
                triggered = True
                should_crash = True

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=args.encode() if args else b"",
            should_crash=should_crash,
            error_message="MLSD buffer overflow detected" if triggered else "",
            state_at_trigger=current_state,
            state_violation=state_violation
        )


class CVE_2017_7692_Handler(CVEHandler):
    """
    CVE-2017-7692: Path traversal vulnerability.
    Path traversal via malformed FTP commands.
    Requires: Authentication for file operations
    """

    def __init__(self):
        super().__init__(CVEInfo(
            cve_id="CVE-2017-7692",
            name="FTP Path Traversal",
            description="Path traversal via malformed directory commands",
            severity=CVESeverity.HIGH,
            affected_command="*",
            trigger_pattern=r"(RMD|MKD|DELE|RNFR|RNTO)\s+\.\./",
            cvss_score=8.1,
            required_states={FTPProtocolState.AUTHENTICATED, FTPProtocolState.PASSIVE_MODE, FTPProtocolState.ACTIVE_MODE},
            requires_authentication=True
        ))

    def check_trigger(self, command: str, args: str, data: bytes,
                     current_state: Optional[str] = None) -> CVETriggerResult:
        """Check for path traversal trigger."""
        triggered = False
        should_crash = False

        cmd_upper = command.upper()
        path_commands = ["RMD", "MKD", "DELE", "RNFR", "RNTO", "RETR", "STOR"]

        if cmd_upper in path_commands:
            # Check for various path traversal patterns
            traversal_patterns = [
                "../", "..\\", "%2e%2e/", "%2e%2e%2f",
                "....//", "..%252f", "%c0%ae%c0%ae/"
            ]

            for pattern in traversal_patterns:
                if pattern.lower() in args.lower():
                    triggered = True
                    # Crash on access to critical paths
                    if "/etc/" in args or "/root/" in args or "C:\\Windows" in args:
                        should_crash = True
                    break

        return CVETriggerResult(
            triggered=triggered,
            cve_id=self.cve_info.cve_id,
            payload=args.encode() if args else b"",
            should_crash=should_crash,
            error_message="Path traversal detected" if triggered else "",
            state_at_trigger=current_state
        )


class CVERegistry:
    """Registry for managing CVE handlers with state-aware checking."""

    def __init__(self):
        self._handlers: Dict[str, CVEHandler] = {}
        self._initialize_handlers()

    def _initialize_handlers(self):
        """Initialize all CVE handlers."""
        handlers = [
            # 2024 CVEs (newest)
            CVE_2024_46483_Handler(),  # Xlight FTP Heap Overflow (CVSS 9.8)
            CVE_2024_4040_Handler(),   # CrushFTP SSTI/RCE (CVSS 9.8)
            CVE_2024_48651_Handler(),  # ProFTPD mod_sql Privilege Escalation (CVSS 7.5)
            # 2023 CVEs
            CVE_2023_51713_Handler(),  # ProFTPD OOB Read DoS (CVSS 7.5)
            # 2022 CVEs
            CVE_2022_34977_Handler(),  # PureFTPd Buffer Overflow (CVSS 9.8)
            # 2019 CVEs (still commonly found in the wild)
            CVE_2019_12815_Handler(),  # ProFTPD mod_copy (CVSS 9.8)
            CVE_2019_18217_Handler(),  # ProFTPD CWD crash (CVSS 7.5)
            # Older but still relevant
            CVE_2015_3306_Handler(),   # ProFTPD mod_copy file read (CVSS 7.5)
            CVE_2010_4221_Handler(),   # ProFTPD Telnet IAC overflow (CVSS 10.0)
            CVE_2017_7692_Handler(),   # FTP Path Traversal (CVSS 8.1)
        ]

        for handler in handlers:
            self._handlers[handler.cve_info.cve_id] = handler

    def get_handler(self, cve_id: str) -> Optional[CVEHandler]:
        """Get a specific CVE handler."""
        return self._handlers.get(cve_id)

    def get_all_handlers(self) -> Dict[str, CVEHandler]:
        """Get all registered handlers."""
        return self._handlers.copy()

    def check_all(self, command: str, args: str, data: bytes = None,
                 current_state: Optional[str] = None) -> List[CVETriggerResult]:
        """Check all CVE handlers for triggers with state awareness."""
        results = []
        for handler in self._handlers.values():
            result = handler.check_trigger(command, args, data, current_state)
            if result.triggered:
                handler.record_trigger(result)
                results.append(result)
        return results

    def check_valid_in_state(self, cve_id: str, current_state: str) -> bool:
        """Check if a CVE can be triggered in the current state."""
        handler = self._handlers.get(cve_id)
        if handler:
            return handler.is_valid_state(current_state)
        return True

    def get_cves_for_state(self, current_state: str) -> List[str]:
        """Get list of CVEs that can be triggered in the current state."""
        valid_cves = []
        for cve_id, handler in self._handlers.items():
            if handler.is_valid_state(current_state):
                valid_cves.append(cve_id)
        return valid_cves

    def get_statistics(self) -> Dict[str, Dict]:
        """Get trigger statistics for all CVEs including state info."""
        stats = {}
        for cve_id, handler in self._handlers.items():
            stats[cve_id] = {
                "name": handler.cve_info.name,
                "severity": handler.cve_info.severity.value,
                "cvss_score": handler.cve_info.cvss_score,
                "trigger_count": handler.trigger_count,
                "last_triggered": handler.last_triggered.isoformat() if handler.last_triggered else None,
                "required_states": [s.value for s in handler.cve_info.required_states],
                "requires_authentication": handler.cve_info.requires_authentication,
                "requires_data_mode": handler.cve_info.requires_data_mode,
                "triggers_by_state": handler._triggers_by_state,
            }
        return stats

    def reset_statistics(self):
        """Reset all trigger statistics."""
        for handler in self._handlers.values():
            handler.trigger_count = 0
            handler.last_triggered = None
            handler._triggers_by_state = {}
