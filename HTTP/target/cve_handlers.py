"""
CVE Vulnerability Handlers for HTTP Target Server

This module simulates 10 real HTTP-related CVE vulnerabilities from 2024-2025 for fuzzing testing.
Each handler contains intentional vulnerabilities that can be triggered by specific payloads.
"""

import re
import os
import sys
import json
import base64
import urllib.parse
from typing import Tuple, Optional, Dict, Any
from flask import Request, Response


class CVEHandler:
    """Base class for CVE vulnerability handlers."""

    def __init__(self, cve_id: str, description: str):
        self.cve_id = cve_id
        self.description = description
        self.triggered = False
        self.trigger_count = 0

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Check if the request triggers the vulnerability.

        Args:
            request: Flask request object

        Returns:
            Tuple of (triggered, payload_info, metadata)
        """
        raise NotImplementedError

    def reset(self):
        """Reset the trigger state."""
        self.triggered = False


class CVE_2024_27316_Handler(CVEHandler):
    """
    CVE-2024-27316: Apache HTTP/2 CONTINUATION Flood DoS

    HTTP/2 CONTINUATION frames can be used to cause memory exhaustion.
    Affects Apache HTTP Server 2.4.17-2.4.58.
    """

    def __init__(self):
        super().__init__(
            "CVE-2024-27316",
            "Apache HTTP/2 CONTINUATION Flood DoS"
        )
        self.continuation_count = 0
        self.threshold = 50

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check for HTTP/2 continuation simulation via headers
        if request.headers.get('X-HTTP2-Continuation') == 'true':
            self.continuation_count += 1
            if self.continuation_count >= self.threshold:
                self.triggered = True
                self.trigger_count += 1
                return True, f"CONTINUATION flood: {self.continuation_count}", {
                    "type": "continuation_flood",
                    "count": self.continuation_count
                }

        # Check for large header blocks (simulates CONTINUATION attack)
        total_header_size = sum(len(str(k)) + len(str(v)) for k, v in request.headers)
        if total_header_size > 16384:  # 16KB header limit
            self.triggered = True
            self.trigger_count += 1
            return True, f"Large header block: {total_header_size} bytes", {
                "type": "header_overflow",
                "size": total_header_size
            }

        # Check for many small headers (HPACK bomb simulation)
        if len(list(request.headers)) > 100:
            self.triggered = True
            self.trigger_count += 1
            return True, f"Header count overflow: {len(list(request.headers))}", {
                "type": "header_count_overflow"
            }

        return False, None, None


class CVE_2024_24795_Handler(CVEHandler):
    """
    CVE-2024-24795: Apache HTTP Response Splitting

    HTTP Response Splitting via mod_rewrite, mod_proxy and related modules.
    Affects Apache HTTP Server through 2.4.58.
    """

    SPLITTING_PATTERNS = [
        r'%0d%0a',      # URL encoded CRLF
        r'%0d',         # URL encoded CR
        r'%0a',         # URL encoded LF
        r'\r\n',        # Raw CRLF
        r'%e5%98%8a',   # Unicode CRLF bypass
        r'%e5%98%8d',   # Unicode CR bypass
    ]

    def __init__(self):
        super().__init__(
            "CVE-2024-24795",
            "Apache HTTP Response Splitting"
        )
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.SPLITTING_PATTERNS]

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check URL path and query string
        full_url = request.full_path
        raw_uri = request.environ.get('RAW_URI', request.path)

        for pattern in self.compiled_patterns:
            if pattern.search(full_url) or pattern.search(raw_uri):
                self.triggered = True
                self.trigger_count += 1
                return True, full_url, {"pattern": pattern.pattern, "type": "url_splitting"}

        # Check Referer and Location-related headers
        check_headers = ['Referer', 'X-Forwarded-Host', 'X-Original-URL', 'Destination']
        for header in check_headers:
            value = request.headers.get(header, '')
            for pattern in self.compiled_patterns:
                if pattern.search(value):
                    self.triggered = True
                    self.trigger_count += 1
                    return True, value, {"pattern": pattern.pattern, "header": header}

        return False, None, None


class CVE_2024_38476_Handler(CVEHandler):
    """
    CVE-2024-38476: Apache mod_proxy Backend Response Information Disclosure

    Malformed backend responses can cause information disclosure.
    Affects Apache HTTP Server 2.4.0-2.4.59.
    """

    def __init__(self):
        super().__init__(
            "CVE-2024-38476",
            "Apache mod_proxy Information Disclosure"
        )

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check for proxy-related headers with malformed values
        proxy_headers = [
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'X-Forwarded-Proto',
            'Via',
            'Forwarded',
        ]

        for header in proxy_headers:
            value = request.headers.get(header, '')
            # Check for malformed proxy header values
            if value:
                # Internal IP disclosure attempt
                internal_patterns = [
                    r'10\.\d+\.\d+\.\d+',
                    r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+',
                    r'192\.168\.\d+\.\d+',
                    r'127\.0\.0\.1',
                    r'localhost',
                    r'\[::1\]',
                ]
                for pattern in internal_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        self.triggered = True
                        self.trigger_count += 1
                        return True, value, {"header": header, "type": "internal_ip_leak"}

                # Check for header injection in proxy headers
                if '\x00' in value or len(value) > 4096:
                    self.triggered = True
                    self.trigger_count += 1
                    return True, value[:100], {"header": header, "type": "malformed_proxy_header"}

        return False, None, None


class CVE_2024_38477_Handler(CVEHandler):
    """
    CVE-2024-38477: Apache mod_proxy Null Pointer Dereference

    Malformed requests can cause null pointer dereference via mod_proxy.
    Affects Apache HTTP Server 2.4.0-2.4.59.
    """

    def __init__(self):
        super().__init__(
            "CVE-2024-38477",
            "Apache mod_proxy Null Pointer Dereference"
        )

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check for null bytes and malformed requests that cause NPE
        path = request.path

        # Null byte in path
        if '\x00' in path:
            self.triggered = True
            self.trigger_count += 1
            return True, path, {"type": "null_byte_path"}

        # Empty or malformed Host header
        host = request.headers.get('Host', '')
        if not host or host == '' or '\x00' in host:
            self.triggered = True
            self.trigger_count += 1
            return True, f"Host: {host}", {"type": "malformed_host"}

        # Check for malformed Content-Length
        cl = request.headers.get('Content-Length', '')
        if cl:
            try:
                cl_int = int(cl)
                if cl_int < 0:
                    self.triggered = True
                    self.trigger_count += 1
                    return True, f"Content-Length: {cl}", {"type": "negative_content_length"}
            except ValueError:
                self.triggered = True
                self.trigger_count += 1
                return True, f"Content-Length: {cl}", {"type": "invalid_content_length"}

        return False, None, None


class CVE_2024_4577_Handler(CVEHandler):
    """
    CVE-2024-4577: PHP CGI Argument Injection

    Argument injection vulnerability in PHP CGI on Windows.
    Allows remote code execution via URL parameters.
    """

    INJECTION_PATTERNS = [
        r'-d\s+allow_url_include',
        r'-d\s+auto_prepend_file',
        r'-d\s+auto_append_file',
        r'-n\s+-d',
        r'-r\s+',  # Run PHP code
        r'%AD',    # Soft hyphen bypass
        r'%ad',
    ]

    def __init__(self):
        super().__init__(
            "CVE-2024-4577",
            "PHP CGI Argument Injection RCE"
        )
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_PATTERNS]

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check query string for PHP CGI argument injection
        query_string = request.query_string.decode('utf-8', errors='ignore')
        full_url = request.full_path

        for pattern in self.compiled_patterns:
            if pattern.search(query_string) or pattern.search(full_url):
                self.triggered = True
                self.trigger_count += 1
                return True, query_string, {"pattern": pattern.pattern, "type": "cgi_injection"}

        # Check for php-cgi specific paths
        if 'php-cgi' in request.path.lower() or 'php.cgi' in request.path.lower():
            if '=' in query_string and '-' in query_string:
                self.triggered = True
                self.trigger_count += 1
                return True, query_string, {"type": "php_cgi_path"}

        return False, None, None


class CVE_2024_23897_Handler(CVEHandler):
    """
    CVE-2024-23897: Jenkins CLI Arbitrary File Read

    Jenkins CLI allows reading arbitrary files via @/path syntax.
    Critical vulnerability allowing secrets/credential theft.
    """

    FILE_READ_PATTERNS = [
        r'@/',           # Direct file read
        r'@\\',          # Windows path
        r'@/etc/',       # Unix sensitive paths
        r'@/proc/',      # Proc filesystem
        r'@C:\\',        # Windows paths
        r'@%2f',         # URL encoded
    ]

    def __init__(self):
        super().__init__(
            "CVE-2024-23897",
            "Jenkins CLI Arbitrary File Read"
        )
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.FILE_READ_PATTERNS]

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check all inputs for @ file read syntax
        check_values = [
            request.path,
            request.query_string.decode('utf-8', errors='ignore'),
        ]

        # Add all header values
        for _, value in request.headers:
            check_values.append(str(value))

        # Check body if present
        try:
            body = request.get_data(as_text=True)
            if body:
                check_values.append(body)
        except Exception:
            pass

        for value in check_values:
            for pattern in self.compiled_patterns:
                if pattern.search(value):
                    self.triggered = True
                    self.trigger_count += 1
                    return True, value[:200], {"pattern": pattern.pattern, "type": "file_read"}

        return False, None, None


class CVE_2024_50379_Handler(CVEHandler):
    """
    CVE-2024-50379: Apache Tomcat Race Condition RCE

    Race condition in JSP compilation allows code execution.
    Affects Apache Tomcat 9.0.0.M1-9.0.95, 10.1.0-M1-10.1.33, 11.0.0-M1-11.0.1.
    """

    def __init__(self):
        super().__init__(
            "CVE-2024-50379",
            "Apache Tomcat Race Condition RCE"
        )
        self.request_times = []
        self.race_window = 0.1  # 100ms window

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        import time

        # Check for JSP-related paths
        path = request.path.lower()
        if '.jsp' in path or '.jspx' in path:
            current_time = time.time()

            # Clean old timestamps
            self.request_times = [t for t in self.request_times if current_time - t < self.race_window]
            self.request_times.append(current_time)

            # Check for rapid requests (race condition simulation)
            if len(self.request_times) >= 3:
                self.triggered = True
                self.trigger_count += 1
                return True, f"Rapid JSP requests: {len(self.request_times)}", {
                    "type": "race_condition",
                    "path": path
                }

        # Check for PUT/write attempts to JSP paths
        if request.method in ['PUT', 'POST'] and '.jsp' in path:
            self.triggered = True
            self.trigger_count += 1
            return True, f"{request.method} to JSP: {path}", {"type": "jsp_write"}

        return False, None, None


class CVE_2024_21733_Handler(CVEHandler):
    """
    CVE-2024-21733: Apache Tomcat Information Disclosure

    Incomplete POST request handling leads to response data leakage.
    Affects Apache Tomcat 8.5.7-8.5.63, 9.0.0-M11-9.0.43.
    """

    def __init__(self):
        super().__init__(
            "CVE-2024-21733",
            "Apache Tomcat Information Disclosure"
        )

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check for incomplete POST with Content-Length mismatch
        if request.method == 'POST':
            cl_header = request.headers.get('Content-Length', '')
            if cl_header:
                try:
                    expected_length = int(cl_header)
                    actual_body = request.get_data()
                    actual_length = len(actual_body)

                    # Content-Length mismatch indicates incomplete request
                    if expected_length > actual_length and expected_length - actual_length > 10:
                        self.triggered = True
                        self.trigger_count += 1
                        return True, f"CL: {expected_length}, Actual: {actual_length}", {
                            "type": "incomplete_post",
                            "expected": expected_length,
                            "actual": actual_length
                        }
                except (ValueError, Exception):
                    pass

        # Check for Transfer-Encoding issues with incomplete chunks
        te = request.headers.get('Transfer-Encoding', '')
        if 'chunked' in te.lower():
            try:
                body = request.get_data(as_text=True)
                # Check for malformed chunked encoding
                if not body.endswith('0\r\n\r\n') and body:
                    self.triggered = True
                    self.trigger_count += 1
                    return True, "Incomplete chunked body", {"type": "incomplete_chunked"}
            except Exception:
                pass

        return False, None, None


class CVE_2024_53677_Handler(CVEHandler):
    """
    CVE-2024-53677: Apache Struts Path Traversal/RCE

    Path traversal vulnerability in file upload functionality.
    Similar to S2-066, allows arbitrary file write leading to RCE.
    """

    TRAVERSAL_PATTERNS = [
        r'\.\./\.\.',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e/',
        r'\.%2e/',
        r'%2e\./',
        r'\.\.%2f',
        r'%252e%252e',
        r'%c0%ae',      # Overlong UTF-8
        r'%c1%1c',      # Overlong UTF-8
    ]

    def __init__(self):
        super().__init__(
            "CVE-2024-53677",
            "Apache Struts Path Traversal RCE"
        )
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.TRAVERSAL_PATTERNS]

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check path for traversal
        full_path = request.full_path
        raw_path = urllib.parse.unquote(full_path)
        double_decoded = urllib.parse.unquote(raw_path)

        for check_path in [full_path, raw_path, double_decoded]:
            for pattern in self.compiled_patterns:
                if pattern.search(check_path):
                    self.triggered = True
                    self.trigger_count += 1
                    return True, check_path, {"pattern": pattern.pattern, "type": "path_traversal"}

        # Check Content-Disposition header for filename traversal (file upload)
        cd = request.headers.get('Content-Disposition', '')
        if cd:
            for pattern in self.compiled_patterns:
                if pattern.search(cd):
                    self.triggered = True
                    self.trigger_count += 1
                    return True, cd, {"pattern": pattern.pattern, "type": "filename_traversal"}

        # Check for Struts action paths
        if '.action' in request.path or '.do' in request.path:
            for pattern in self.compiled_patterns:
                if pattern.search(full_path):
                    self.triggered = True
                    self.trigger_count += 1
                    return True, full_path, {"type": "struts_traversal"}

        return False, None, None


class CVE_2025_24813_Handler(CVEHandler):
    """
    CVE-2025-24813: Apache Tomcat Partial PUT Request RCE

    Partial PUT request handling allows arbitrary file write and RCE.
    Most recent critical vulnerability affecting Tomcat 9.0.0.M1-9.0.98,
    10.1.0-M1-10.1.34, 11.0.0-M1-11.0.2.
    """

    def __init__(self):
        super().__init__(
            "CVE-2025-24813",
            "Apache Tomcat Partial PUT RCE"
        )

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        # Check for PUT requests with partial content
        if request.method == 'PUT':
            content_range = request.headers.get('Content-Range', '')

            # Check for partial PUT (Content-Range header)
            if content_range:
                self.triggered = True
                self.trigger_count += 1
                return True, f"Partial PUT: {content_range}", {
                    "type": "partial_put",
                    "range": content_range
                }

            # Check for dangerous file extensions
            path = request.path.lower()
            dangerous_extensions = ['.jsp', '.jspx', '.war', '.jar', '.class', '.xml']
            for ext in dangerous_extensions:
                if path.endswith(ext):
                    self.triggered = True
                    self.trigger_count += 1
                    return True, f"PUT to {ext}: {path}", {"type": "dangerous_put", "extension": ext}

        # Check for session deserialization attacks via PUT
        if request.method == 'PUT' and '/sessions/' in request.path:
            self.triggered = True
            self.trigger_count += 1
            return True, f"Session PUT: {request.path}", {"type": "session_manipulation"}

        return False, None, None


def get_all_handlers() -> list:
    """
    Get instances of all CVE handlers.

    Returns:
        List of CVEHandler instances
    """
    return [
        CVE_2024_27316_Handler(),   # Apache HTTP/2 CONTINUATION Flood DoS
        CVE_2024_24795_Handler(),   # Apache HTTP Response Splitting
        CVE_2024_38476_Handler(),   # Apache mod_proxy Information Disclosure
        CVE_2024_38477_Handler(),   # Apache mod_proxy Null Pointer Dereference
        CVE_2024_4577_Handler(),    # PHP CGI Argument Injection RCE
        CVE_2024_23897_Handler(),   # Jenkins CLI Arbitrary File Read
        CVE_2024_50379_Handler(),   # Apache Tomcat Race Condition RCE
        CVE_2024_21733_Handler(),   # Apache Tomcat Information Disclosure
        CVE_2024_53677_Handler(),   # Apache Struts Path Traversal RCE
        CVE_2025_24813_Handler(),   # Apache Tomcat Partial PUT RCE
    ]
