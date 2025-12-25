"""
Configuration settings for the FTP Fuzzing Framework.
"""
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class OllamaConfig:
    """Ollama LLM configuration."""
    host: str = "http://localhost:11434"
    seed_model: str = "qwen3:8b"
    mutation_model: str = "qwen3:8b"  # Using qwen3:8b as qwen3-vl:8b alternative
    timeout: int = 120
    temperature: float = 0.7
    max_tokens: int = 2048


@dataclass
class FTPServerConfig:
    """FTP target server configuration."""
    host: str = "127.0.0.1"
    port: int = 2121
    username: str = "anonymous"
    password: str = "anonymous@"
    root_dir: str = "./ftp_root"
    max_cons: int = 10
    max_cons_per_ip: int = 5
    passive_ports: tuple = (60000, 60100)
    restart_delay: float = 1.0
    crash_log_dir: str = "./results/crashes"


@dataclass
class FuzzerConfig:
    """Fuzzer configuration."""
    target_host: str = "127.0.0.1"
    target_port: int = 2121
    session_name: str = "ftp_fuzz"
    results_dir: str = "./results"
    max_iterations: int = 10000
    timeout: float = 5.0
    restart_threshold: int = 3
    seed_pool_size: int = 100
    mutation_rounds: int = 10

    # Boofuzz specific
    recv_timeout: float = 5.0
    crash_threshold_request: int = 3
    crash_threshold_element: int = 3


@dataclass
class MetricsConfig:
    """Metrics and logging configuration."""
    log_level: str = "INFO"
    log_file: str = "./results/fuzzer.log"
    metrics_file: str = "./results/metrics.json"
    crash_log_file: str = "./results/crashes.json"
    save_interval: int = 100  # Save metrics every N iterations


@dataclass
class Settings:
    """Main settings container."""
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    ftp_server: FTPServerConfig = field(default_factory=FTPServerConfig)
    fuzzer: FuzzerConfig = field(default_factory=FuzzerConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)

    # CVE configurations
    enabled_cves: List[str] = field(default_factory=lambda: [
        "CVE-2020-9273",   # ProFTPD use-after-free
        "CVE-2019-12815",  # ProFTPD mod_copy
        "CVE-2015-3306",   # ProFTPD mod_copy arbitrary file read
        "CVE-2010-4221",   # ProFTPD buffer overflow
        "CVE-2011-4130",   # ProFTPD use-after-free in response pool
        "CVE-2019-18217",  # ProFTPD CWD command crash
        "CVE-2021-46854",  # ProFTPD memory leak
        "CVE-2020-9272",   # ProFTPD out-of-bounds read
        "CVE-2022-34977",  # PureFTPd buffer overflow
        "CVE-2017-7692",   # SquirrelMail path traversal (FTP related)
    ])

    def __post_init__(self):
        """Create necessary directories."""
        Path(self.fuzzer.results_dir).mkdir(parents=True, exist_ok=True)
        Path(self.ftp_server.crash_log_dir).mkdir(parents=True, exist_ok=True)
        Path(self.ftp_server.root_dir).mkdir(parents=True, exist_ok=True)


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def load_settings_from_env() -> Settings:
    """Load settings from environment variables."""
    global _settings

    ollama_config = OllamaConfig(
        host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        seed_model=os.getenv("OLLAMA_SEED_MODEL", "qwen3:8b"),
        mutation_model=os.getenv("OLLAMA_MUTATION_MODEL", "qwen3:8b"),
    )

    ftp_config = FTPServerConfig(
        host=os.getenv("FTP_HOST", "127.0.0.1"),
        port=int(os.getenv("FTP_PORT", "2121")),
    )

    fuzzer_config = FuzzerConfig(
        target_host=os.getenv("FUZZER_TARGET_HOST", "127.0.0.1"),
        target_port=int(os.getenv("FUZZER_TARGET_PORT", "2121")),
        max_iterations=int(os.getenv("FUZZER_MAX_ITERATIONS", "10000")),
    )

    _settings = Settings(
        ollama=ollama_config,
        ftp_server=ftp_config,
        fuzzer=fuzzer_config,
    )

    return _settings
