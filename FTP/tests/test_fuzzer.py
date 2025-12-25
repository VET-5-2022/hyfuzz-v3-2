"""
Unit tests for the fuzzer components.
"""
import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fuzzer.base_fuzzer import FTPCommand, FuzzerConfig, FuzzerType
from fuzzer.baseline_boofuzz import BoofuzzMutators


class TestFTPCommand:
    """Tests for FTPCommand class."""

    def test_to_bytes(self):
        """Test command serialization."""
        cmd = FTPCommand(name="USER", args="anonymous")
        assert cmd.to_bytes() == b"USER anonymous\r\n"

    def test_to_bytes_no_args(self):
        """Test command without arguments."""
        cmd = FTPCommand(name="PWD", args="")
        assert cmd.to_bytes() == b"PWD\r\n"

    def test_from_string(self):
        """Test command parsing."""
        cmd = FTPCommand.from_string("USER anonymous")
        assert cmd.name == "USER"
        assert cmd.args == "anonymous"

    def test_from_string_no_args(self):
        """Test parsing command without args."""
        cmd = FTPCommand.from_string("QUIT")
        assert cmd.name == "QUIT"
        assert cmd.args == ""


class TestBoofuzzMutators:
    """Tests for boofuzz mutation strategies."""

    def test_string_mutators_not_empty(self):
        """Test that string mutators are generated."""
        mutations = BoofuzzMutators.string_mutators()
        assert len(mutations) > 0

    def test_path_mutators_contain_traversal(self):
        """Test path mutations include traversal patterns."""
        mutations = BoofuzzMutators.path_mutators()
        assert any("../" in m for m in mutations)

    def test_site_mutators_contain_cpfr(self):
        """Test SITE mutations include mod_copy commands."""
        mutations = BoofuzzMutators.site_mutators()
        assert any("CPFR" in m for m in mutations)

    def test_apply_random_mutation(self):
        """Test random mutation application."""
        original = "test"
        mutated = BoofuzzMutators.apply_random_mutation(original)
        # Mutation should return something (may be same or different)
        assert mutated is not None


class TestFuzzerConfig:
    """Tests for FuzzerConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = FuzzerConfig()
        assert config.target_host == "127.0.0.1"
        assert config.target_port == 2121
        assert config.timeout == 5.0

    def test_custom_values(self):
        """Test custom configuration."""
        config = FuzzerConfig(
            target_host="192.168.1.1",
            target_port=21,
            max_iterations=5000
        )
        assert config.target_host == "192.168.1.1"
        assert config.target_port == 21
        assert config.max_iterations == 5000


class TestFuzzerType:
    """Tests for FuzzerType enum."""

    def test_all_types_exist(self):
        """Test all fuzzer types are defined."""
        assert FuzzerType.BASELINE.value == "baseline"
        assert FuzzerType.LLM_SEED.value == "llm_seed"
        assert FuzzerType.LLM_MUTATION.value == "llm_mutation"
        assert FuzzerType.LLM_FULL.value == "llm_full"
        assert FuzzerType.FEEDBACK.value == "feedback"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
