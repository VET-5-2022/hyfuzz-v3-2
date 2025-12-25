"""
LLM Seed Generation Fuzzer.
Uses boofuzz to generate initial seed pool, then LLM updates the pool periodically.
Mutations are performed using boofuzz.
This is variant #2 in the ablation study.
"""
import random
import logging
import hashlib
from typing import List, Dict, Any

from .base_fuzzer import BaseFuzzer, FuzzerType, FuzzerConfig, FTPCommand, FuzzResult
from .baseline_boofuzz import BoofuzzMutators
from .llm_client import OllamaClient


class LLMSeedFuzzer(BaseFuzzer):
    """
    Fuzzer that uses boofuzz for initial seed pool generation,
    then LLM updates the seed pool periodically.
    Mutations are performed using boofuzz.

    Ablation Study Variant #2:
    - Initial Seed Pool: Boofuzz (10 seeds)
    - Seed Pool Update: LLM (every 10 iterations)
    - Mutation: Boofuzz standard
    """

    # Configuration
    SEED_POOL_SIZE = 10
    LLM_UPDATE_INTERVAL = 10  # Update seed pool every N iterations

    def __init__(
        self,
        config: FuzzerConfig = None,
        metrics_collector=None,
        ollama_host: str = "http://localhost:11434",
        seed_model: str = "qwen3:8b",
    ):
        super().__init__(
            fuzzer_type=FuzzerType.LLM_SEED,
            config=config,
            metrics_collector=metrics_collector,
        )

        # Initialize LLM client
        self.llm_client = OllamaClient(
            host=ollama_host,
            seed_model=seed_model,
        )

        # Boofuzz mutators for mutation phase
        self._mutators = BoofuzzMutators()

        # Seed pool (fixed size, updated by LLM)
        self._seed_pool: List[FTPCommand] = []

        # Statistics
        self._llm_updates = 0
        self._boofuzz_seeds_generated = 0

    def generate_seeds(self) -> List[FTPCommand]:
        """Generate initial seed pool using boofuzz patterns."""
        logging.info(f"Generating initial seed pool using boofuzz ({self.SEED_POOL_SIZE} seeds)...")

        # Use boofuzz to generate state-aware seeds
        all_seeds = self._generate_boofuzz_seeds()

        # Select SEED_POOL_SIZE seeds, ensuring state diversity
        self._seed_pool = self._select_diverse_seeds(all_seeds, self.SEED_POOL_SIZE)
        self._boofuzz_seeds_generated = len(self._seed_pool)

        logging.info(f"Initial seed pool: {len(self._seed_pool)} seeds")

        # Record metrics
        self.metrics.record_seed_generation(
            self.fuzzer_type.value,
            self.session_id,
            len(self._seed_pool),
            from_llm=False
        )

        return self._seed_pool

    def _generate_boofuzz_seeds(self) -> List[FTPCommand]:
        """Generate seeds using boofuzz patterns with FTP state awareness."""
        seeds = []

        # State-aware seed templates
        # Pre-auth commands (CONNECTED state)
        pre_auth_seeds = [
            ("USER", "anonymous"),
            ("USER", "admin"),
            ("USER", "root"),
            ("USER", "ftp"),
            ("USER", "admin'--"),  # CVE-2024-48651
            ("USER", "' OR '1'='1"),
            ("SYST", ""),
            ("FEAT", ""),
        ]

        # Auth commands (USER_SENT state)
        auth_seeds = [
            ("PASS", "anonymous@"),
            ("PASS", "password"),
            ("PASS", "' OR '1'='1"),  # CVE-2024-48651
        ]

        # Post-auth commands (AUTHENTICATED state)
        post_auth_seeds = [
            ("CWD", "/"),
            ("CWD", "../../../etc"),
            ("CWD", "/tmp\\"),  # CVE-2023-51713
            ("PWD", ""),
            ("MKD", "testdir"),
            ("MKD", "dir'\\"),  # CVE-2023-51713
            ("SITE", "CPFR /etc/passwd"),  # CVE-2019-12815
            ("SITE", "CPFR ${config}"),  # CVE-2024-4040
            ("PASV", ""),
            ("TYPE", "A"),
        ]

        # Data transfer commands (PASSIVE_MODE/ACTIVE_MODE state)
        transfer_seeds = [
            ("LIST", ""),
            ("LIST", "${dir}"),  # CVE-2024-4040
            ("NLST", ""),
            ("RETR", "welcome.txt"),
            ("RETR", "sessions.obj"),  # CVE-2024-4040
            ("RETR", "../../../etc/passwd"),
            ("STOR", "upload.txt"),
            ("MLSD", ""),
            ("MLSD", "A" * 600),  # CVE-2022-34977
        ]

        # Buffer overflow seeds (any state)
        overflow_seeds = [
            ("USER", "A" * 1500),  # CVE-2024-46483
            ("CWD", "B" * 1500),
            ("MLSD", "C" * 2500),
        ]

        for cmd, args in (pre_auth_seeds + auth_seeds + post_auth_seeds +
                          transfer_seeds + overflow_seeds):
            seeds.append(FTPCommand(name=cmd, args=args))

        return seeds

    def _select_diverse_seeds(self, seeds: List[FTPCommand], count: int) -> List[FTPCommand]:
        """Select diverse seeds covering different FTP states and commands."""
        if len(seeds) <= count:
            return seeds.copy()

        # Group by command type
        by_command: Dict[str, List[FTPCommand]] = {}
        for seed in seeds:
            if seed.name not in by_command:
                by_command[seed.name] = []
            by_command[seed.name].append(seed)

        # Select from each group
        selected = []
        commands = list(by_command.keys())
        random.shuffle(commands)

        while len(selected) < count and any(by_command.values()):
            for cmd in commands:
                if by_command.get(cmd) and len(selected) < count:
                    selected.append(by_command[cmd].pop(0))

        return selected

    def _update_seed_pool_with_llm(self) -> bool:
        """Use LLM to update the seed pool with new seeds."""
        if not self.llm_client.is_available:
            return False

        logging.info(f"Updating seed pool with LLM (iteration {self._current_iteration})...")

        # Get current state for context
        current_state = self.get_current_state() or "AUTHENTICATED"

        # Generate new seeds from LLM
        llm_seeds, response = self.llm_client.generate_seeds(count=self.SEED_POOL_SIZE)

        if response.success:
            # Record LLM metrics
            self.metrics.record_llm_request(
                self.fuzzer_type.value,
                self.session_id,
                response.tokens_used,
                response.latency_ms
            )

            # Parse and replace seed pool
            new_pool = []
            for seed_str in llm_seeds:
                cmd = FTPCommand.from_string(seed_str)
                if cmd.name:
                    new_pool.append(cmd)

            if new_pool:
                # Replace the entire pool with LLM-generated seeds
                self._seed_pool = new_pool[:self.SEED_POOL_SIZE]
                self._llm_updates += 1
                logging.info(f"Seed pool updated: {len(self._seed_pool)} seeds (update #{self._llm_updates})")

                # Record metrics
                self.metrics.record_seed_generation(
                    self.fuzzer_type.value,
                    self.session_id,
                    len(self._seed_pool),
                    from_llm=True
                )
                return True

        logging.warning(f"LLM seed pool update failed: {response.error}")
        return False

    def mutate(self, seed: FTPCommand) -> FTPCommand:
        """Mutate a seed using boofuzz-style mutations."""
        strategies = ["string", "path", "random", "combine"]
        strategy = random.choice(strategies)

        mutated_args = seed.args

        if strategy == "string":
            mutations = self._mutators.string_mutators()
            mutated_args = random.choice(mutations)

        elif strategy == "path":
            if seed.name in ["CWD", "RETR", "STOR", "DELE", "RMD", "MKD"]:
                mutations = self._mutators.path_mutators()
                mutated_args = random.choice(mutations)

        elif strategy == "random":
            mutated_args = self._mutators.apply_random_mutation(seed.args)

        elif strategy == "combine":
            mutations = self._mutators.string_mutators()
            mutation = random.choice(mutations)
            mutated_args = seed.args + mutation

        # Record mutation (from boofuzz, not LLM)
        self.metrics.record_mutation(
            self.fuzzer_type.value,
            self.session_id,
            strategy,
            from_llm=False
        )

        return FTPCommand(name=seed.name, args=mutated_args)

    def run(self, iterations: int = None) -> List[FuzzResult]:
        """Run the LLM seed fuzzer."""
        iterations = iterations or self.config.max_iterations

        # Start metrics session
        self.metrics.start_session(self.fuzzer_type.value, self.session_id)

        # Generate initial seeds using boofuzz
        if not self._seed_pool:
            self.generate_seeds()

        # Warm up LLM for later updates
        if self.llm_client.is_available:
            logging.info("Warming up LLM model...")
            self.llm_client.warmup(models=[self.llm_client.seed_model])

        # Connect to server
        if not self.connect():
            logging.error("Failed to connect to FTP server")
            return []

        # Authenticate
        if not self.authenticate():
            logging.error("Failed to authenticate")
            return []

        logging.info(f"Starting LLM seed fuzzer for {iterations} iterations")
        logging.info(f"Seed pool size: {len(self._seed_pool)}, "
                    f"LLM update interval: {self.LLM_UPDATE_INTERVAL}")

        results = []

        for i in range(iterations):
            self._current_iteration = i

            # Update seed pool with LLM every N iterations
            if self.llm_client.is_available and (i + 1) % self.LLM_UPDATE_INTERVAL == 0:
                self._update_seed_pool_with_llm()

            # Select seed from pool
            seed = random.choice(self._seed_pool)

            # Apply boofuzz mutation (70% chance)
            if random.random() < 0.7:
                command = self.mutate(seed)
            else:
                command = seed

            # Send command
            result = self.send_command(command)
            results.append(result)
            self._results.append(result)

            # Generate payload hash for unique tracking
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
                            f"Seed pool: {len(self._seed_pool)} | "
                            f"LLM updates: {self._llm_updates}")

        self.disconnect()

        logging.info(f"Completed {iterations} iterations with {self._llm_updates} LLM pool updates")
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzer statistics."""
        stats = super().get_statistics()
        stats["seed_pool_size"] = len(self._seed_pool)
        stats["seed_pool_max_size"] = self.SEED_POOL_SIZE
        stats["llm_updates"] = self._llm_updates
        stats["llm_update_interval"] = self.LLM_UPDATE_INTERVAL
        stats["boofuzz_seeds_generated"] = self._boofuzz_seeds_generated
        stats["seed_source"] = "boofuzz (initial) + llm (updates)"
        stats["mutation_source"] = "boofuzz"
        return stats
