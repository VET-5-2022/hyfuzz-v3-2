"""
LLM Full Fuzzer.
Uses boofuzz for initial seed and mutation pools, then LLM updates both pools periodically.
This is variant #4 in the ablation study.
"""
import random
import logging
import hashlib
from typing import List, Dict, Any

from .base_fuzzer import BaseFuzzer, FuzzerType, FuzzerConfig, FTPCommand, FuzzResult
from .baseline_boofuzz import BoofuzzMutators
from .llm_client import OllamaClient


class LLMFullFuzzer(BaseFuzzer):
    """
    Fuzzer that uses boofuzz for initial pools,
    then LLM updates both seed and mutation pools periodically.

    Ablation Study Variant #4:
    - Initial Seed Pool: Boofuzz (10 seeds)
    - Initial Mutation Pool: Boofuzz (10 mutations)
    - Pool Updates: LLM updates both pools every 10 iterations
    """

    # Configuration
    SEED_POOL_SIZE = 10
    MUTATION_POOL_SIZE = 10
    LLM_UPDATE_INTERVAL = 10  # Update pools every N iterations

    def __init__(
        self,
        config: FuzzerConfig = None,
        metrics_collector=None,
        ollama_host: str = "http://localhost:11434",
        seed_model: str = "qwen3:8b",
        mutation_model: str = "qwen3:8b",
    ):
        super().__init__(
            fuzzer_type=FuzzerType.LLM_FULL,
            config=config,
            metrics_collector=metrics_collector,
        )

        # Initialize LLM client
        self.llm_client = OllamaClient(
            host=ollama_host,
            seed_model=seed_model,
            mutation_model=mutation_model,
        )

        self._mutators = BoofuzzMutators()

        # Dual pools (fixed size, updated by LLM)
        self._seed_pool: List[FTPCommand] = []
        self._mutation_pool: List[str] = []

        # Statistics
        self._llm_seed_updates = 0
        self._llm_mutation_updates = 0
        self._mutations_applied = 0

    def generate_seeds(self) -> List[FTPCommand]:
        """Initialize seed pool using boofuzz patterns."""
        logging.info(f"Initializing seed pool with boofuzz ({self.SEED_POOL_SIZE} seeds)...")

        all_seeds = self._generate_boofuzz_seeds()
        self._seed_pool = self._select_diverse(all_seeds, self.SEED_POOL_SIZE)

        self.metrics.record_seed_generation(
            self.fuzzer_type.value,
            self.session_id,
            len(self._seed_pool),
            from_llm=False
        )

        logging.info(f"Seed pool initialized: {len(self._seed_pool)} seeds")
        return self._seed_pool

    def _generate_boofuzz_seeds(self) -> List[FTPCommand]:
        """Generate seeds using boofuzz patterns with FTP state awareness."""
        seeds = []

        # State-aware seeds targeting 2024 CVEs
        templates = [
            # Pre-auth (CONNECTED)
            ("USER", "anonymous"),
            ("USER", "admin"),
            ("USER", "admin'--"),  # CVE-2024-48651
            ("USER", "' OR '1'='1"),
            ("SYST", ""),
            ("FEAT", ""),

            # Auth (USER_SENT)
            ("PASS", "anonymous@"),
            ("PASS", "' OR '1'='1"),

            # Post-auth (AUTHENTICATED)
            ("CWD", "/"),
            ("CWD", "/tmp\\"),  # CVE-2023-51713
            ("CWD", "../../../etc"),
            ("PWD", ""),
            ("MKD", "testdir"),
            ("MKD", "dir'\\"),
            ("SITE", "CPFR /etc/passwd"),  # CVE-2019-12815
            ("SITE", "CPFR ${config}"),  # CVE-2024-4040
            ("PASV", ""),

            # Data transfer (PASSIVE_MODE)
            ("LIST", ""),
            ("RETR", "welcome.txt"),
            ("RETR", "sessions.obj"),  # CVE-2024-4040
            ("MLSD", ""),
            ("MLSD", "A" * 600),  # CVE-2022-34977

            # Heap overflow
            ("USER", "A" * 1500),  # CVE-2024-46483
            ("CWD", "B" * 1500),
        ]

        for cmd, args in templates:
            seeds.append(FTPCommand(name=cmd, args=args))

        return seeds

    def _init_mutation_pool(self):
        """Initialize mutation pool using boofuzz patterns."""
        logging.info(f"Initializing mutation pool with boofuzz ({self.MUTATION_POOL_SIZE} mutations)...")

        pool = []

        # CVE-2024-46483: Heap overflow
        pool.append("A" * 1500)
        pool.append("B" * 2000 + "\xff\xff\xff")

        # CVE-2024-4040: Template injection
        pool.append("${config}")
        pool.append("{{7*7}}")
        pool.append("sessions.obj")

        # CVE-2024-48651: SQL injection
        pool.append("admin'--")
        pool.append("' OR '1'='1")

        # CVE-2023-51713: Quote/backslash
        pool.append("/tmp\\")
        pool.append("file'\\")

        # CVE-2019-12815: Path traversal
        pool.append("../../../etc/passwd")

        self._mutation_pool = pool[:self.MUTATION_POOL_SIZE]
        logging.info(f"Mutation pool initialized: {len(self._mutation_pool)} mutations")

    def _select_diverse(self, items: List, count: int) -> List:
        """Select diverse items."""
        if len(items) <= count:
            return items.copy()
        return random.sample(items, count)

    def _update_pools_with_llm(self) -> bool:
        """Use LLM to update both seed and mutation pools."""
        if not self.llm_client.is_available:
            return False

        logging.info(f"Updating both pools with LLM (iteration {self._current_iteration})...")
        success = False

        # Update seed pool
        seed_success = self._update_seed_pool_with_llm()
        if seed_success:
            self._llm_seed_updates += 1
            success = True

        # Update mutation pool
        mutation_success = self._update_mutation_pool_with_llm()
        if mutation_success:
            self._llm_mutation_updates += 1
            success = True

        return success

    def _update_seed_pool_with_llm(self) -> bool:
        """Use LLM to update seed pool."""
        llm_seeds, response = self.llm_client.generate_seeds(count=self.SEED_POOL_SIZE)

        if response.success:
            self.metrics.record_llm_request(
                self.fuzzer_type.value,
                self.session_id,
                response.tokens_used,
                response.latency_ms
            )

            new_pool = []
            for seed_str in llm_seeds:
                cmd = FTPCommand.from_string(seed_str)
                if cmd.name:
                    new_pool.append(cmd)

            if new_pool:
                self._seed_pool = new_pool[:self.SEED_POOL_SIZE]
                logging.info(f"Seed pool updated: {len(self._seed_pool)} seeds")
                return True

        return False

    def _update_mutation_pool_with_llm(self) -> bool:
        """Use LLM to update mutation pool."""
        import re

        prompt = f"""Generate {self.MUTATION_POOL_SIZE} unique FTP fuzzing payloads.

Target vulnerabilities:
- CVE-2024-46483: Heap overflow (long strings >1024 chars, \\xff)
- CVE-2024-4040: Template injection (${{, {{}}}}, sessions.obj)
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
            content = re.sub(r'<think>.*?</think>', '', response.content, flags=re.DOTALL)
            lines = content.strip().split("\n")

            new_mutations = []
            for line in lines:
                line = line.strip()
                line = re.sub(r'^[\d]+[\.\)]\s*', '', line)
                line = re.sub(r'^[-*•]\s*', '', line)
                line = line.strip()

                if line and len(line) < 5000 and not line.startswith('#'):
                    new_mutations.append(line)

            if new_mutations:
                self._mutation_pool = new_mutations[:self.MUTATION_POOL_SIZE]
                logging.info(f"Mutation pool updated: {len(self._mutation_pool)} mutations")
                return True

        return False

    def mutate(self, seed: FTPCommand) -> FTPCommand:
        """Apply a mutation from the mutation pool."""
        if not self._mutation_pool:
            mutated_args = self._mutators.apply_random_mutation(seed.args)
            self.metrics.record_mutation(
                self.fuzzer_type.value, self.session_id, "boofuzz_fallback", from_llm=False
            )
            return FTPCommand(name=seed.name, args=mutated_args)

        mutation = random.choice(self._mutation_pool)

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
        """Run the LLM full fuzzer."""
        iterations = iterations or self.config.max_iterations

        # Start metrics
        self.metrics.start_session(self.fuzzer_type.value, self.session_id)

        # Initialize pools with boofuzz
        if not self._seed_pool:
            self.generate_seeds()

        if not self._mutation_pool:
            self._init_mutation_pool()

        # Warm up LLM
        if self.llm_client.is_available:
            logging.info("Warming up LLM models...")
            self.llm_client.warmup()

        # Connect
        if not self.connect():
            logging.error("Failed to connect")
            return []

        if not self.authenticate():
            logging.error("Failed to authenticate")
            return []

        logging.info(f"Starting LLM full fuzzer for {iterations} iterations")
        logging.info(f"Seed pool: {len(self._seed_pool)}, "
                    f"Mutation pool: {len(self._mutation_pool)}, "
                    f"LLM update interval: {self.LLM_UPDATE_INTERVAL}")

        results = []

        for i in range(iterations):
            self._current_iteration = i

            # Update both pools with LLM every N iterations
            if self.llm_client.is_available and (i + 1) % self.LLM_UPDATE_INTERVAL == 0:
                self._update_pools_with_llm()

            # Select seed from pool
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

            # Record metrics
            payload_hash = hashlib.md5(command.to_bytes()).hexdigest()[:16]
            crash_hash = f"{result.command.name}_{payload_hash}"

            self.metrics.record_iteration(
                self.fuzzer_type.value,
                self.session_id,
                result.success,
                result.response_time_ms,
                method=command.name,
                path=command.args[:100] if command.args else None,
                status_code=result.response_code
            )

            if not result.success:
                error_type = "timeout" if "Timeout" in result.error_message else \
                            "connection" if result.crashed else "general"
                self.metrics.record_error(self.fuzzer_type.value, self.session_id, error_type)

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
                            f"Seed updates: {self._llm_seed_updates}, "
                            f"Mutation updates: {self._llm_mutation_updates}")

        self.disconnect()

        logging.info(f"Completed {iterations} iterations")
        logging.info(f"LLM updates - Seeds: {self._llm_seed_updates}, Mutations: {self._llm_mutation_updates}")

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzer statistics."""
        stats = super().get_statistics()
        stats["seed_pool_size"] = len(self._seed_pool)
        stats["seed_pool_max_size"] = self.SEED_POOL_SIZE
        stats["mutation_pool_size"] = len(self._mutation_pool)
        stats["mutation_pool_max_size"] = self.MUTATION_POOL_SIZE
        stats["llm_seed_updates"] = self._llm_seed_updates
        stats["llm_mutation_updates"] = self._llm_mutation_updates
        stats["llm_update_interval"] = self.LLM_UPDATE_INTERVAL
        stats["mutations_applied"] = self._mutations_applied
        stats["seed_source"] = "boofuzz (initial) + llm (updates)"
        stats["mutation_source"] = "boofuzz (initial) + llm (updates)"
        return stats
