"""
LLM Mutation Fuzzer.
Uses boofuzz for seed generation, LLM maintains a mutation pool.
This is variant #3 in the ablation study.
"""
import random
import logging
import hashlib
from typing import List, Dict, Any

from .base_fuzzer import BaseFuzzer, FuzzerType, FuzzerConfig, FTPCommand, FuzzResult
from .baseline_boofuzz import BoofuzzMutators
from .llm_client import OllamaClient


class LLMMutationFuzzer(BaseFuzzer):
    """
    Fuzzer that uses boofuzz for seed generation,
    and LLM maintains a mutation pool that gets updated periodically.

    Ablation Study Variant #3:
    - Seed Generation: Boofuzz
    - Mutation Pool: 10 mutations (initialized by boofuzz, updated by LLM every 10 iterations)
    """

    # Configuration
    MUTATION_POOL_SIZE = 10
    LLM_UPDATE_INTERVAL = 10  # Update mutation pool every N iterations

    def __init__(
        self,
        config: FuzzerConfig = None,
        metrics_collector=None,
        ollama_host: str = "http://localhost:11434",
        mutation_model: str = "qwen3:8b",
    ):
        super().__init__(
            fuzzer_type=FuzzerType.LLM_MUTATION,
            config=config,
            metrics_collector=metrics_collector,
        )

        # Initialize LLM client
        self.llm_client = OllamaClient(
            host=ollama_host,
            mutation_model=mutation_model,
        )

        # Boofuzz for seed generation
        self._mutators = BoofuzzMutators()

        # Seed pool (from boofuzz)
        self._seed_pool: List[FTPCommand] = []

        # Mutation pool (fixed size, updated by LLM)
        self._mutation_pool: List[str] = []

        # Statistics
        self._llm_updates = 0
        self._mutations_applied = 0

    def generate_seeds(self) -> List[FTPCommand]:
        """Generate seeds using boofuzz patterns with FTP state awareness."""
        logging.info("Generating seeds using boofuzz...")

        seeds = []

        # State-aware seed templates
        command_templates = {
            # Pre-auth (CONNECTED state)
            "USER": ["anonymous", "ftp", "admin", "root", "test"],
            "SYST": [""],
            "FEAT": [""],

            # Post-auth (AUTHENTICATED state)
            "PASS": ["anonymous@", "password", ""],
            "CWD": ["/", "/tmp", ".", "..", "~"],
            "PWD": [""],
            "MKD": ["testdir", "newdir"],
            "RMD": ["testdir"],
            "DELE": ["file.txt"],
            "SITE": ["HELP", "CPFR /etc/passwd", "CPTO /tmp/test"],
            "PASV": [""],
            "PORT": ["127,0,0,1,0,21"],
            "TYPE": ["A", "I"],

            # Data transfer (PASSIVE_MODE/ACTIVE_MODE state)
            "LIST": ["", "/", "."],
            "NLST": ["", "/"],
            "RETR": ["welcome.txt", "readme.txt"],
            "STOR": ["upload.txt"],
            "MLSD": ["", "/"],

            # Session
            "QUIT": [""],
            "NOOP": [""],
        }

        for cmd, args_list in command_templates.items():
            for args in args_list:
                seeds.append(FTPCommand(name=cmd, args=args))

        self._seed_pool = seeds

        # Record metrics
        self.metrics.record_seed_generation(
            self.fuzzer_type.value,
            self.session_id,
            len(seeds),
            from_llm=False
        )

        logging.info(f"Generated {len(seeds)} boofuzz seeds")
        return seeds

    def _init_mutation_pool(self):
        """Initialize the mutation pool using boofuzz patterns."""
        logging.info(f"Initializing mutation pool with boofuzz ({self.MUTATION_POOL_SIZE} mutations)...")

        pool = []

        # CVE-2024-46483: Heap overflow
        pool.append("A" * 1500)
        pool.append("B" * 2000 + "\xff\xff\xff")

        # CVE-2024-4040: Template injection
        pool.append("${config}")
        pool.append("{{7*7}}")

        # CVE-2024-48651: SQL injection
        pool.append("admin'--")
        pool.append("' OR '1'='1")

        # CVE-2023-51713: Quote/backslash
        pool.append("/tmp\\")
        pool.append("file'\\")

        # CVE-2019-12815: Path traversal
        pool.append("../../../etc/passwd")
        pool.append("CPFR /etc/shadow")

        self._mutation_pool = pool[:self.MUTATION_POOL_SIZE]

        logging.info(f"Initialized mutation pool with {len(self._mutation_pool)} mutations")

    def _update_mutation_pool_with_llm(self) -> bool:
        """Use LLM to generate new mutations and update the pool."""
        if not self.llm_client.is_available:
            return False

        logging.info(f"Updating mutation pool with LLM (iteration {self._current_iteration})...")

        # Get current seed for context
        if self._seed_pool:
            seed = random.choice(self._seed_pool)
            seed_str = f"{seed.name} {seed.args}".strip()
        else:
            seed_str = "CWD /tmp"

        # Generate new mutations from LLM
        new_mutations = []

        # Make a single LLM call for multiple mutations
        prompt = f"""Generate {self.MUTATION_POOL_SIZE} unique FTP fuzzing payloads.
Base command: {seed_str}

Target vulnerabilities:
- CVE-2024-46483: Heap overflow (long strings >1024 chars, \\xff)
- CVE-2024-4040: Template injection (${{, {{}}}})
- CVE-2024-48651: SQL injection (admin'--, ' OR '1'='1)
- CVE-2023-51713: OOB read (trailing backslash \\, unbalanced quotes)

Output ONLY the payloads, one per line. No explanations."""

        response = self.llm_client._call_model(
            self.llm_client.mutation_model,
            prompt,
            max_tokens=512
        )

        if response.success and response.content:
            self.metrics.record_llm_request(
                self.fuzzer_type.value,
                self.session_id,
                response.tokens_used,
                response.latency_ms
            )

            # Parse mutations
            import re
            content = re.sub(r'<think>.*?</think>', '', response.content, flags=re.DOTALL)
            lines = content.strip().split("\n")

            for line in lines:
                line = line.strip()
                # Clean prefixes
                line = re.sub(r'^[\d]+[\.\)]\s*', '', line)
                line = re.sub(r'^[-*•]\s*', '', line)
                line = line.strip()

                if line and len(line) < 5000 and not line.startswith('#'):
                    new_mutations.append(line)

            if new_mutations:
                self._mutation_pool = new_mutations[:self.MUTATION_POOL_SIZE]
                self._llm_updates += 1
                logging.info(f"Mutation pool updated: {len(self._mutation_pool)} mutations (update #{self._llm_updates})")
                return True

        logging.warning(f"LLM mutation pool update failed")
        return False

    def mutate(self, seed: FTPCommand) -> FTPCommand:
        """Apply a mutation from the mutation pool."""
        if not self._mutation_pool:
            # Fallback to boofuzz
            mutated_args = self._mutators.apply_random_mutation(seed.args)
            self.metrics.record_mutation(
                self.fuzzer_type.value, self.session_id, "boofuzz_fallback", from_llm=False
            )
            return FTPCommand(name=seed.name, args=mutated_args)

        # Select mutation from pool
        mutation = random.choice(self._mutation_pool)

        # Apply strategy
        strategy = random.choice(["replace", "append", "prepend"])

        if strategy == "replace":
            mutated_args = mutation
        elif strategy == "append":
            mutated_args = seed.args + mutation
        else:
            mutated_args = mutation + seed.args

        self._mutations_applied += 1

        self.metrics.record_mutation(
            self.fuzzer_type.value,
            self.session_id,
            f"pool_{strategy}",
            from_llm=True
        )

        return FTPCommand(name=seed.name, args=mutated_args)

    def run(self, iterations: int = None) -> List[FuzzResult]:
        """Run the LLM mutation fuzzer."""
        iterations = iterations or self.config.max_iterations

        # Start metrics session
        self.metrics.start_session(self.fuzzer_type.value, self.session_id)

        # Generate seeds using boofuzz
        if not self._seed_pool:
            self.generate_seeds()

        # Initialize mutation pool with boofuzz
        if not self._mutation_pool:
            self._init_mutation_pool()

        # Warm up LLM
        if self.llm_client.is_available:
            logging.info("Warming up LLM model...")
            self.llm_client.warmup(models=[self.llm_client.mutation_model])

        # Connect to server
        if not self.connect():
            logging.error("Failed to connect to FTP server")
            return []

        # Authenticate
        if not self.authenticate():
            logging.error("Failed to authenticate")
            return []

        logging.info(f"Starting LLM mutation fuzzer for {iterations} iterations")
        logging.info(f"Seed pool: {len(self._seed_pool)}, "
                    f"Mutation pool: {len(self._mutation_pool)}, "
                    f"LLM update interval: {self.LLM_UPDATE_INTERVAL}")

        results = []

        for i in range(iterations):
            self._current_iteration = i

            # Update mutation pool with LLM every N iterations
            if self.llm_client.is_available and (i + 1) % self.LLM_UPDATE_INTERVAL == 0:
                self._update_mutation_pool_with_llm()

            # Select seed from boofuzz pool
            seed = random.choice(self._seed_pool)

            # Apply mutation (70% chance)
            if random.random() < 0.7:
                command = self.mutate(seed)
            else:
                command = seed

            # Send command
            result = self.send_command(command)
            results.append(result)
            self._results.append(result)

            # Generate payload hash
            payload_hash = hashlib.md5(command.to_bytes()).hexdigest()[:16]
            crash_hash = f"{result.command.name}_{payload_hash}"

            # Record iteration
            self.metrics.record_iteration(
                self.fuzzer_type.value,
                self.session_id,
                result.success,
                result.response_time_ms,
                method=command.name,
                path=command.args[:100] if command.args else None,
                status_code=result.response_code
            )

            # Handle errors
            if not result.success:
                error_type = "timeout" if "Timeout" in result.error_message else \
                            "connection" if result.crashed else "general"
                self.metrics.record_error(self.fuzzer_type.value, self.session_id, error_type)

            # Record crashes and CVE triggers
            if result.crashed or result.cve_triggered:
                self.metrics.record_crash(
                    self.fuzzer_type.value,
                    self.session_id,
                    crash_hash=crash_hash,
                    cve_id=result.cve_triggered,
                    payload_hash=payload_hash
                )
                self._handle_crash(result)

            # Log progress
            if (i + 1) % 100 == 0:
                logging.info(f"Progress: {i + 1}/{iterations} | "
                            f"Mutation pool: {len(self._mutation_pool)} | "
                            f"LLM updates: {self._llm_updates}")

        self.disconnect()

        logging.info(f"Completed {iterations} iterations with {self._llm_updates} mutation pool updates")
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzer statistics."""
        stats = super().get_statistics()
        stats["seed_pool_size"] = len(self._seed_pool)
        stats["mutation_pool_size"] = len(self._mutation_pool)
        stats["mutation_pool_max_size"] = self.MUTATION_POOL_SIZE
        stats["llm_updates"] = self._llm_updates
        stats["llm_update_interval"] = self.LLM_UPDATE_INTERVAL
        stats["mutations_applied"] = self._mutations_applied
        stats["seed_source"] = "boofuzz"
        stats["mutation_source"] = "boofuzz (initial) + llm (updates)"
        return stats
