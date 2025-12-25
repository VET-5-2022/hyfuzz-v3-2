"""
Stateful Fuzzer for FTP Protocol.
Respects FTP state machine while fuzzing, enabling deeper protocol exploration.
"""
import random
import logging
import time
from typing import List, Dict, Any, Optional

from .base_fuzzer import BaseFuzzer, FuzzerType, FuzzerConfig, FTPCommand, FuzzResult
from .baseline_boofuzz import BoofuzzMutators
from .state_machine import FTPStateMachine, FTPState, FTPSequenceGenerator, CommandSequence


class StatefulFuzzer(BaseFuzzer):
    """
    State-aware fuzzer that respects FTP protocol state machine.

    This fuzzer:
    1. Tracks protocol state during fuzzing
    2. Only sends commands valid in current state
    3. Uses command sequences to reach deeper states
    4. Can intentionally violate state for negative testing
    """

    def __init__(
        self,
        config: FuzzerConfig = None,
        metrics_collector = None,
        violation_rate: float = 0.1,  # Rate of intentional state violations
    ):
        # Use a custom fuzzer type
        super().__init__(
            fuzzer_type=FuzzerType.BASELINE,  # Reuse baseline type for metrics
            config=config,
            metrics_collector=metrics_collector,
        )
        # Override the type name
        self._fuzzer_name = "stateful"

        self.state_machine = FTPStateMachine()
        self.sequence_generator = FTPSequenceGenerator(self.state_machine)
        self._mutators = BoofuzzMutators()

        # Configuration
        self.violation_rate = violation_rate

        # State tracking
        self._current_sequence: Optional[CommandSequence] = None
        self._sequence_position: int = 0
        self._sequences_completed: int = 0

        # Coverage tracking
        self._state_coverage: Dict[FTPState, int] = {state: 0 for state in FTPState}
        self._transition_coverage: Dict[str, int] = {}
        self._command_in_state: Dict[tuple, int] = {}  # (state, command) -> count

    @property
    def name(self) -> str:
        return self._fuzzer_name

    def generate_seeds(self) -> List[FTPCommand]:
        """Generate seed sequences instead of individual commands."""
        seeds = []

        # Get pre-defined attack sequences
        attack_sequences = self.sequence_generator.get_attack_sequences()
        for seq in attack_sequences:
            for cmd, args in seq.commands:
                seeds.append(FTPCommand(name=cmd, args=args))

        # Generate random valid sequences
        for _ in range(10):
            seq = self.sequence_generator.generate_valid_sequence(length=random.randint(3, 8))
            for cmd, args in seq.commands:
                seeds.append(FTPCommand(name=cmd, args=args))

        self._seed_pool = seeds
        return seeds

    def mutate(self, seed: FTPCommand) -> FTPCommand:
        """Mutate command while considering current state."""
        # Get valid commands for current state
        valid_commands = self.state_machine.get_valid_commands()

        # Decide whether to stay in valid state or violate
        if random.random() < self.violation_rate:
            # Intentional violation - use any command
            strategies = ["string", "path", "random"]
        else:
            # Stay valid - only mutate args, keep command appropriate
            if seed.name not in valid_commands and valid_commands:
                # Switch to a valid command
                seed = FTPCommand(name=random.choice(valid_commands), args=seed.args)
            strategies = ["string", "path"]

        strategy = random.choice(strategies)
        mutated_args = seed.args

        if strategy == "string":
            mutations = self._mutators.string_mutators()
            mutated_args = random.choice(mutations)
        elif strategy == "path":
            if seed.name in ["CWD", "RETR", "STOR", "DELE", "RMD", "MKD"]:
                mutations = self._mutators.path_mutators()
                mutated_args = random.choice(mutations)
        else:
            mutated_args = self._mutators.apply_random_mutation(seed.args)

        return FTPCommand(name=seed.name, args=mutated_args)

    def _execute_sequence(self, sequence: CommandSequence) -> List[FuzzResult]:
        """Execute a full command sequence."""
        results = []

        for cmd, args in sequence.commands:
            command = FTPCommand(name=cmd, args=args)

            # Track state before command
            state_before = self.state_machine.current_state
            self._state_coverage[state_before] += 1
            self._command_in_state[(state_before, cmd)] = \
                self._command_in_state.get((state_before, cmd), 0) + 1

            # Send command
            result = self.send_command(command)
            results.append(result)
            self._results.append(result)

            # Update state machine
            response_code = result.response_code
            new_state = self.state_machine.execute(cmd, response_code)

            # Track transition
            transition_key = f"{state_before.name}->{cmd}->{new_state.name}"
            self._transition_coverage[transition_key] = \
                self._transition_coverage.get(transition_key, 0) + 1

            # Log state transition
            self.logger.logger.debug(
                f"State: {state_before.name} --[{cmd}]--> {new_state.name} (code: {response_code})"
            )

            # Handle crash
            if result.crashed:
                self._handle_crash(result)
                break

            # Check for disconnection
            if new_state == FTPState.DISCONNECTED:
                break

        return results

    def _select_next_sequence(self) -> CommandSequence:
        """Select the next sequence to execute based on coverage."""
        strategies = ["attack", "random_valid", "invalid", "coverage_guided"]
        strategy = random.choices(
            strategies,
            weights=[0.3, 0.3, 0.1, 0.3]
        )[0]

        if strategy == "attack":
            sequences = self.sequence_generator.get_attack_sequences()
            return random.choice(sequences)

        elif strategy == "random_valid":
            return self.sequence_generator.generate_valid_sequence(
                length=random.randint(3, 10)
            )

        elif strategy == "invalid":
            return self.sequence_generator.generate_invalid_sequence()

        else:  # coverage_guided
            return self._generate_coverage_guided_sequence()

    def _generate_coverage_guided_sequence(self) -> CommandSequence:
        """Generate sequence targeting uncovered states/transitions."""
        # Find least covered states
        min_coverage = min(self._state_coverage.values()) if self._state_coverage else 0
        target_states = [
            state for state, count in self._state_coverage.items()
            if count <= min_coverage + 5
        ]

        if not target_states:
            return self.sequence_generator.generate_valid_sequence()

        target_state = random.choice(target_states)

        # Generate sequence to reach target state
        commands = [("USER", "anonymous"), ("PASS", "anonymous@")]

        # Add commands to reach target state
        if target_state in [FTPState.PASSIVE_MODE, FTPState.ACTIVE_MODE]:
            commands.append(("PASV", ""))
        elif target_state == FTPState.RENAMING:
            commands.append(("RNFR", "test.txt"))

        # Add exploration commands
        valid_cmds = []
        for cmd, transition in self.state_machine.transitions.items():
            if target_state in transition.from_states:
                valid_cmds.append(cmd)

        if valid_cmds:
            for _ in range(3):
                cmd = random.choice(valid_cmds)
                args = self.sequence_generator._generate_args_for_command(cmd)
                commands.append((cmd, args))

        return CommandSequence(
            commands=commands,
            description=f"Coverage-guided to {target_state.name}"
        )

    def run(self, iterations: int = None) -> List[FuzzResult]:
        """Run stateful fuzzing."""
        iterations = iterations or self.config.max_iterations

        self.metrics.start_session(self._fuzzer_name, self.session_id)

        # Generate seed sequences
        self.generate_seeds()

        logging.info(f"Starting stateful fuzzer for {iterations} iterations")
        logging.info(f"State violation rate: {self.violation_rate}")

        results = []
        sequence_count = 0

        while self._current_iteration < iterations:
            # Connect and setup
            if not self._connected:
                if not self.connect():
                    logging.error("Failed to connect")
                    time.sleep(1)
                    continue
                self.state_machine.set_connected()

            # Select and execute sequence
            sequence = self._select_next_sequence()
            sequence_count += 1

            self.logger.logger.info(
                f"Executing sequence {sequence_count}: {sequence.description or 'random'}"
            )

            try:
                import hashlib
                seq_results = self._execute_sequence(sequence)
                results.extend(seq_results)
                self._sequences_completed += 1

                # Record iterations with detailed metrics
                for result in seq_results:
                    self._current_iteration += 1

                    # Generate payload hash for unique tracking
                    payload_hash = hashlib.md5(result.command.to_bytes()).hexdigest()[:16]
                    crash_hash = f"{result.command.name}_{payload_hash}"

                    self.metrics.record_iteration(
                        self._fuzzer_name,
                        self.session_id,
                        result.success,
                        result.response_time_ms,
                        method=result.command.name,
                        path=result.command.args[:100] if result.command.args else None,
                        status_code=result.response_code
                    )

                    # Handle errors
                    if not result.success:
                        if "Timeout" in result.error_message:
                            self.metrics.record_error(self._fuzzer_name, self.session_id, "timeout")
                        elif "Connection" in result.error_message or result.crashed:
                            self.metrics.record_error(self._fuzzer_name, self.session_id, "connection")
                        else:
                            self.metrics.record_error(self._fuzzer_name, self.session_id, "general")

                    if result.crashed or result.cve_triggered:
                        self.metrics.record_crash(
                            self._fuzzer_name,
                            self.session_id,
                            crash_hash=crash_hash,
                            cve_id=result.cve_triggered,
                            payload_hash=payload_hash
                        )

            except Exception as e:
                logging.error(f"Sequence execution error: {e}")
                self.disconnect()
                self.state_machine.reset()

            # Reset for next sequence
            self.disconnect()
            self.state_machine.reset()

            # Log progress
            if sequence_count % 10 == 0:
                logging.info(
                    f"Progress: {self._current_iteration}/{iterations} iterations, "
                    f"{sequence_count} sequences, "
                    f"States covered: {sum(1 for v in self._state_coverage.values() if v > 0)}"
                )

        self.metrics.end_session(self._fuzzer_name, self.session_id)
        logging.info(f"Completed {self._current_iteration} iterations in {sequence_count} sequences")

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzer statistics including state coverage."""
        stats = super().get_statistics()
        stats["fuzzer_type"] = self._fuzzer_name
        stats["sequences_completed"] = self._sequences_completed
        stats["state_coverage"] = {
            state.name: count for state, count in self._state_coverage.items()
        }
        stats["unique_transitions"] = len(self._transition_coverage)
        stats["transition_coverage"] = self._transition_coverage
        stats["command_state_pairs"] = len(self._command_in_state)
        stats["violation_rate"] = self.violation_rate
        return stats

    def get_coverage_report(self) -> Dict[str, Any]:
        """Generate detailed coverage report."""
        total_states = len(FTPState)
        covered_states = sum(1 for v in self._state_coverage.values() if v > 0)

        total_transitions = len(self.state_machine.transitions) * total_states  # Approximate
        covered_transitions = len(self._transition_coverage)

        return {
            "state_coverage": {
                "total": total_states,
                "covered": covered_states,
                "percentage": covered_states / total_states * 100,
                "details": {s.name: c for s, c in self._state_coverage.items()}
            },
            "transition_coverage": {
                "unique_transitions": covered_transitions,
                "details": self._transition_coverage
            },
            "command_state_pairs": {
                "total": len(self._command_in_state),
                "details": {f"{s.name}:{c}": n for (s, c), n in self._command_in_state.items()}
            }
        }
