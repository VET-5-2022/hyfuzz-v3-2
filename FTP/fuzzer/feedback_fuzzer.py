"""
Feedback-driven Fuzzer.
Uses boofuzz seeds and mutations with LLM adjusting weights based on feedback.
This is variant #5 in the ablation study.
"""
import random
import logging
import hashlib
from typing import List, Dict, Any
from collections import defaultdict

from .base_fuzzer import BaseFuzzer, FuzzerType, FuzzerConfig, FTPCommand, FuzzResult
from .baseline_boofuzz import BoofuzzMutators
from .llm_client import OllamaClient


class FeedbackFuzzer(BaseFuzzer):
    """
    Fuzzer that uses boofuzz for both seeds and mutations,
    with LLM adjusting weights based on target feedback.

    Ablation Study Variant #5:
    - Seed Pool: 10 seeds from boofuzz (with LLM-adjusted weights)
    - Mutation Pool: 10 mutations from boofuzz (with LLM-adjusted weights)
    - Strategy: LLM adjusts weights every 10 iterations based on feedback
    """

    # Configuration
    SEED_POOL_SIZE = 10
    MUTATION_POOL_SIZE = 10
    LLM_UPDATE_INTERVAL = 10  # Adjust weights every N iterations

    def __init__(
        self,
        config: FuzzerConfig = None,
        metrics_collector=None,
        ollama_host: str = "http://localhost:11434",
        strategy_model: str = "qwen3:8b",
    ):
        super().__init__(
            fuzzer_type=FuzzerType.FEEDBACK,
            config=config,
            metrics_collector=metrics_collector,
        )

        # Initialize LLM client for weight adjustments
        self.llm_client = OllamaClient(
            host=ollama_host,
            mutation_model=strategy_model,
        )

        self._mutators = BoofuzzMutators()

        # Fixed-size pools with weights
        self._seed_pool: List[FTPCommand] = []
        self._seed_weights: List[float] = []  # Weights for each seed

        self._mutation_pool: List[str] = []
        self._mutation_weights: List[float] = []  # Weights for each mutation

        # Feedback tracking
        self._recent_responses: List[str] = []
        self._crash_commands: Dict[str, int] = defaultdict(int)
        self._effective_seeds: Dict[int, int] = defaultdict(int)  # seed_index -> crash_count
        self._effective_mutations: Dict[int, int] = defaultdict(int)  # mutation_index -> crash_count
        self._total_crashes = 0
        self._cves_found: List[str] = []

        # Statistics
        self._llm_weight_updates = 0
        self._last_seed_index = -1
        self._last_mutation_index = -1

    def generate_seeds(self) -> List[FTPCommand]:
        """Initialize seed pool with 10 boofuzz seeds."""
        logging.info(f"Initializing seed pool with boofuzz ({self.SEED_POOL_SIZE} seeds)...")

        # State-aware boofuzz seeds targeting 2024 CVEs
        all_seeds = [
            # Pre-auth (CONNECTED) - CVE-2024-48651
            FTPCommand("USER", "anonymous"),
            FTPCommand("USER", "admin'--"),
            FTPCommand("USER", "' OR '1'='1"),

            # Auth (USER_SENT)
            FTPCommand("PASS", "anonymous@"),
            FTPCommand("PASS", "' OR '1'='1"),

            # Post-auth (AUTHENTICATED)
            FTPCommand("CWD", "/tmp\\"),  # CVE-2023-51713
            FTPCommand("CWD", "../../../etc"),
            FTPCommand("MKD", "dir'\\"),  # CVE-2023-51713
            FTPCommand("SITE", "CPFR /etc/passwd"),  # CVE-2019-12815
            FTPCommand("SITE", "CPFR ${config}"),  # CVE-2024-4040

            # Data transfer (PASSIVE_MODE)
            FTPCommand("RETR", "sessions.obj"),  # CVE-2024-4040
            FTPCommand("MLSD", "A" * 600),  # CVE-2022-34977

            # Heap overflow - CVE-2024-46483
            FTPCommand("USER", "A" * 1500),
            FTPCommand("CWD", "B" * 1500),
        ]

        # Select SEED_POOL_SIZE seeds
        self._seed_pool = all_seeds[:self.SEED_POOL_SIZE]

        # Initialize equal weights (sum to 1.0)
        self._seed_weights = [1.0 / self.SEED_POOL_SIZE] * self.SEED_POOL_SIZE

        self.metrics.record_seed_generation(
            self.fuzzer_type.value,
            self.session_id,
            len(self._seed_pool),
            from_llm=False
        )

        logging.info(f"Seed pool initialized: {len(self._seed_pool)} seeds with equal weights")
        return self._seed_pool

    def _init_mutation_pool(self):
        """Initialize mutation pool with 10 boofuzz mutations."""
        logging.info(f"Initializing mutation pool with boofuzz ({self.MUTATION_POOL_SIZE} mutations)...")

        # 10 diverse mutations targeting 2024 CVEs
        self._mutation_pool = [
            # CVE-2024-46483: Heap overflow
            "A" * 1500,
            "B" * 2000 + "\xff\xff\xff",

            # CVE-2024-4040: Template injection
            "${config}",
            "{{7*7}}",
            "sessions.obj",

            # CVE-2024-48651: SQL injection
            "admin'--",
            "' OR '1'='1",

            # CVE-2023-51713: Quote/backslash
            "/tmp\\",
            "file'\\",

            # CVE-2019-12815: Path traversal
            "../../../etc/passwd",
        ]

        # Initialize equal weights
        self._mutation_weights = [1.0 / self.MUTATION_POOL_SIZE] * self.MUTATION_POOL_SIZE

        logging.info(f"Mutation pool initialized: {len(self._mutation_pool)} mutations with equal weights")

    def _select_seed(self) -> tuple:
        """Select a seed based on current weights. Returns (seed, index)."""
        if not self._seed_pool:
            return None, -1

        # Normalize weights
        total = sum(self._seed_weights)
        if total <= 0:
            # Reset to equal weights if all zero
            self._seed_weights = [1.0 / len(self._seed_pool)] * len(self._seed_pool)
            total = 1.0

        normalized = [w / total for w in self._seed_weights]

        # Select based on weights
        index = random.choices(range(len(self._seed_pool)), weights=normalized)[0]
        return self._seed_pool[index], index

    def _select_mutation(self) -> tuple:
        """Select a mutation based on current weights. Returns (mutation, index)."""
        if not self._mutation_pool:
            return None, -1

        # Normalize weights
        total = sum(self._mutation_weights)
        if total <= 0:
            self._mutation_weights = [1.0 / len(self._mutation_pool)] * len(self._mutation_pool)
            total = 1.0

        normalized = [w / total for w in self._mutation_weights]

        # Select based on weights
        index = random.choices(range(len(self._mutation_pool)), weights=normalized)[0]
        return self._mutation_pool[index], index

    def mutate(self, seed: FTPCommand) -> FTPCommand:
        """Apply a mutation from the weighted mutation pool."""
        mutation, index = self._select_mutation()
        self._last_mutation_index = index

        if mutation is None:
            mutated_args = self._mutators.apply_random_mutation(seed.args)
            self.metrics.record_mutation(
                self.fuzzer_type.value, self.session_id, "boofuzz_fallback", from_llm=False
            )
            return FTPCommand(name=seed.name, args=mutated_args)

        # Apply mutation strategy
        strategy = random.choice(["replace", "append", "prepend"])

        if strategy == "replace":
            mutated_args = mutation
        elif strategy == "append":
            mutated_args = seed.args + mutation
        else:
            mutated_args = mutation + seed.args

        self.metrics.record_mutation(
            self.fuzzer_type.value,
            self.session_id,
            f"weighted_pool_{strategy}",
            from_llm=False
        )

        return FTPCommand(name=seed.name, args=mutated_args)

    def _record_feedback(self, result: FuzzResult):
        """Record feedback from a fuzzing result."""
        # Store response
        response_str = result.response.decode('utf-8', errors='replace')[:200]
        self._recent_responses.append(f"{result.command.name}: {response_str}")

        if len(self._recent_responses) > 50:
            self._recent_responses = self._recent_responses[-50:]

        # Track crashes and boost effective seeds/mutations
        if result.crashed or result.cve_triggered:
            self._total_crashes += 1
            self._crash_commands[result.command.name] += 1

            # Boost seed weight
            if self._last_seed_index >= 0:
                self._effective_seeds[self._last_seed_index] += 1
                # Increase weight by 10%
                self._seed_weights[self._last_seed_index] *= 1.1

            # Boost mutation weight
            if self._last_mutation_index >= 0:
                self._effective_mutations[self._last_mutation_index] += 1
                self._mutation_weights[self._last_mutation_index] *= 1.1

        # Track CVEs
        if result.cve_triggered and result.cve_triggered not in self._cves_found:
            self._cves_found.append(result.cve_triggered)

    def _update_weights_with_llm(self):
        """Use LLM to adjust seed and mutation weights based on feedback."""
        if not self.llm_client.is_available:
            return

        logging.info(f"Updating weights with LLM (iteration {self._current_iteration})...")

        # Prepare feedback summary
        effective_info = {
            "seeds": {i: self._effective_seeds[i] for i in range(len(self._seed_pool))
                     if self._effective_seeds[i] > 0},
            "mutations": {i: self._effective_mutations[i] for i in range(len(self._mutation_pool))
                         if self._effective_mutations[i] > 0},
            "crash_commands": dict(self._crash_commands),
            "cves_found": self._cves_found,
        }

        # Get strategy recommendation from LLM
        strategy, response = self.llm_client.get_feedback_strategy(
            iterations=self._current_iteration,
            crashes=self._total_crashes,
            cves=self._cves_found,
            effective_commands=dict(self._crash_commands),
            recent_responses=self._recent_responses[-10:],
        )

        if response.success:
            self._llm_weight_updates += 1

            self.metrics.record_llm_request(
                self.fuzzer_type.value,
                self.session_id,
                response.tokens_used,
                response.latency_ms
            )

            # Apply LLM suggestions to weights
            if "mutation_priorities" in strategy:
                priorities = strategy["mutation_priorities"]
                # Map priorities to mutation indices based on type
                type_map = {
                    "heap_overflow": [0, 1],  # First two mutations
                    "template_injection": [2, 3, 4],
                    "sql_injection": [5, 6],
                    "quote_backslash": [7, 8],
                    "path_traversal": [9],
                }

                for i, priority in enumerate(priorities):
                    if priority in type_map:
                        for idx in type_map[priority]:
                            if idx < len(self._mutation_weights):
                                # Higher priority = higher weight boost
                                boost = 1.0 + (0.3 - i * 0.05)
                                self._mutation_weights[idx] *= boost

            logging.info(f"Weights updated by LLM (update #{self._llm_weight_updates})")

    def run(self, iterations: int = None) -> List[FuzzResult]:
        """Run the feedback-driven fuzzer."""
        iterations = iterations or self.config.max_iterations

        # Start metrics
        self.metrics.start_session(self.fuzzer_type.value, self.session_id)

        # Initialize pools
        if not self._seed_pool:
            self.generate_seeds()

        if not self._mutation_pool:
            self._init_mutation_pool()

        # Warm up LLM
        if self.llm_client.is_available:
            logging.info("Warming up LLM model...")
            self.llm_client.warmup(models=[self.llm_client.mutation_model])

        # Connect
        if not self.connect():
            logging.error("Failed to connect")
            return []

        if not self.authenticate():
            logging.error("Failed to authenticate")
            return []

        logging.info(f"Starting feedback fuzzer for {iterations} iterations")
        logging.info(f"Seed pool: {len(self._seed_pool)}, "
                    f"Mutation pool: {len(self._mutation_pool)}, "
                    f"LLM update interval: {self.LLM_UPDATE_INTERVAL}")

        results = []

        for i in range(iterations):
            self._current_iteration = i

            # Update weights with LLM every N iterations
            if self.llm_client.is_available and (i + 1) % self.LLM_UPDATE_INTERVAL == 0:
                self._update_weights_with_llm()

            # Select seed based on weights
            seed, seed_idx = self._select_seed()
            self._last_seed_index = seed_idx

            if seed is None:
                continue

            # Apply mutation (70% chance)
            if random.random() < 0.7:
                command = self.mutate(seed)
            else:
                command = seed
                self._last_mutation_index = -1

            # Send command
            result = self.send_command(command)
            results.append(result)
            self._results.append(result)

            # Record feedback (updates weights based on crash/CVE)
            self._record_feedback(result)

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
                            f"Crashes: {self._total_crashes} | "
                            f"LLM updates: {self._llm_weight_updates}")

        self.disconnect()

        logging.info(f"Completed {iterations} iterations")
        logging.info(f"Crashes: {self._total_crashes}, LLM weight updates: {self._llm_weight_updates}")

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzer statistics."""
        stats = super().get_statistics()
        stats["seed_pool_size"] = len(self._seed_pool)
        stats["seed_pool_max_size"] = self.SEED_POOL_SIZE
        stats["mutation_pool_size"] = len(self._mutation_pool)
        stats["mutation_pool_max_size"] = self.MUTATION_POOL_SIZE
        stats["llm_weight_updates"] = self._llm_weight_updates
        stats["llm_update_interval"] = self.LLM_UPDATE_INTERVAL
        stats["total_crashes"] = self._total_crashes
        stats["cves_found"] = self._cves_found
        stats["seed_weights"] = self._seed_weights
        stats["mutation_weights"] = self._mutation_weights
        stats["effective_seeds"] = dict(self._effective_seeds)
        stats["effective_mutations"] = dict(self._effective_mutations)
        stats["seed_source"] = "boofuzz (10 seeds, LLM-weighted)"
        stats["mutation_source"] = "boofuzz (10 mutations, LLM-weighted)"
        return stats
