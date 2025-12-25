"""
Logging utilities for the FTP Fuzzing Framework.
"""
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

from rich.logging import RichHandler
from rich.console import Console


# Global console instance
console = Console()


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    rich_output: bool = True,
) -> logging.Logger:
    """
    Setup logging configuration for the framework.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
        rich_output: Whether to use rich formatting for console output

    Returns:
        Configured root logger
    """
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    root_logger.handlers = []

    # Console handler
    if rich_output:
        console_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True,
        )
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )

    root_logger.addHandler(console_handler)

    # Suppress pyftpdlib INFO logs (connection opened/closed messages)
    # These are noisy and not useful during fuzzing
    logging.getLogger("pyftpdlib").setLevel(logging.WARNING)

    # File handler
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )
        root_logger.addHandler(file_handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the given name.

    Args:
        name: Logger name

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


class FuzzerLogger:
    """
    Specialized logger for fuzzer operations.
    Provides structured logging for fuzzing events.
    """

    def __init__(self, fuzzer_name: str, log_dir: str = "./results/logs"):
        self.fuzzer_name = fuzzer_name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = get_logger(f"fuzzer.{fuzzer_name}")

        # Session-specific log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_file = self.log_dir / f"{fuzzer_name}_{timestamp}.log"

        # Add session file handler
        file_handler = logging.FileHandler(self.session_file)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            )
        )
        self.logger.addHandler(file_handler)

    def log_iteration(self, iteration: int, command: str, result: str):
        """Log a fuzzing iteration."""
        self.logger.debug(f"[{iteration}] {command} -> {result}")

    def log_crash(self, iteration: int, command: str, payload: bytes, error: str):
        """Log a crash event."""
        self.logger.warning(
            f"[{iteration}] CRASH: {command} | Payload: {payload[:100]}... | Error: {error}"
        )

    def log_cve_trigger(self, iteration: int, cve_id: str, command: str):
        """Log a CVE trigger event."""
        self.logger.info(f"[{iteration}] CVE TRIGGERED: {cve_id} via {command}")

    def log_seed_generation(self, count: int, source: str):
        """Log seed generation event."""
        self.logger.info(f"Generated {count} seeds from {source}")

    def log_mutation(self, original: str, mutated: str, strategy: str):
        """Log mutation event."""
        self.logger.debug(f"Mutation ({strategy}): {original[:50]}... -> {mutated[:50]}...")

    def log_llm_request(self, model: str, prompt_preview: str, tokens: int):
        """Log LLM API request."""
        self.logger.debug(f"LLM Request ({model}): {prompt_preview[:100]}... | Tokens: {tokens}")

    def log_llm_response(self, model: str, response_preview: str, latency_ms: float):
        """Log LLM API response."""
        self.logger.debug(f"LLM Response ({model}): {response_preview[:100]}... | Latency: {latency_ms:.2f}ms")

    def log_summary(self, stats: dict):
        """Log session summary."""
        self.logger.info("=" * 50)
        self.logger.info(f"Session Summary for {self.fuzzer_name}")
        self.logger.info("=" * 50)
        for key, value in stats.items():
            self.logger.info(f"  {key}: {value}")
        self.logger.info("=" * 50)
