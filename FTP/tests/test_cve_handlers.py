"""
Unit tests for CVE handlers.
"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from target.cve_handlers import (
    CVERegistry,
    CVE_2020_9273_Handler,
    CVE_2019_12815_Handler,
    CVE_2010_4221_Handler,
    CVE_2019_18217_Handler,
    CVE_2022_34977_Handler,
    CVESeverity
)


class TestCVERegistry:
    """Tests for CVE registry."""

    def test_all_cves_registered(self):
        """Test all 10 CVEs are registered."""
        registry = CVERegistry()
        handlers = registry.get_all_handlers()
        assert len(handlers) == 10

    def test_get_specific_handler(self):
        """Test retrieving specific CVE handler."""
        registry = CVERegistry()
        handler = registry.get_handler("CVE-2020-9273")
        assert handler is not None
        assert handler.cve_info.cve_id == "CVE-2020-9273"


class TestCVE_2020_9273:
    """Tests for use-after-free CVE."""

    def test_trigger_on_null_bytes(self):
        """Test trigger on multiple null bytes."""
        handler = CVE_2020_9273_Handler()
        result = handler.check_trigger(
            "STOR",
            "file.txt",
            b"\x00" * 100
        )
        assert result.triggered is True
        assert result.cve_id == "CVE-2020-9273"

    def test_no_trigger_on_normal_data(self):
        """Test no trigger on normal data."""
        handler = CVE_2020_9273_Handler()
        result = handler.check_trigger(
            "STOR",
            "file.txt",
            b"normal data"
        )
        assert result.triggered is False


class TestCVE_2019_12815:
    """Tests for mod_copy CVE."""

    def test_trigger_on_cpfr_traversal(self):
        """Test trigger on SITE CPFR with traversal."""
        handler = CVE_2019_12815_Handler()
        result = handler.check_trigger(
            "SITE",
            "CPFR ../../../etc/passwd",
            None
        )
        assert result.triggered is True

    def test_trigger_on_cpto(self):
        """Test trigger on SITE CPTO."""
        handler = CVE_2019_12815_Handler()
        result = handler.check_trigger(
            "SITE",
            "CPTO /etc/shadow",
            None
        )
        assert result.triggered is True

    def test_no_trigger_on_help(self):
        """Test no trigger on SITE HELP."""
        handler = CVE_2019_12815_Handler()
        result = handler.check_trigger(
            "SITE",
            "HELP",
            None
        )
        assert result.triggered is False


class TestCVE_2010_4221:
    """Tests for IAC overflow CVE."""

    def test_trigger_on_iac_sequence(self):
        """Test trigger on telnet IAC sequences."""
        handler = CVE_2010_4221_Handler()
        # Multiple IAC (0xFF) bytes
        result = handler.check_trigger(
            "USER",
            "test",
            b"\xff" * 50
        )
        assert result.triggered is True

    def test_crash_on_long_iac(self):
        """Test crash trigger on long IAC sequence."""
        handler = CVE_2010_4221_Handler()
        result = handler.check_trigger(
            "USER",
            "test",
            b"\xff" * 200
        )
        assert result.triggered is True
        assert result.should_crash is True


class TestCVE_2019_18217:
    """Tests for CWD crash CVE."""

    def test_trigger_on_deep_traversal(self):
        """Test trigger on deep path traversal."""
        handler = CVE_2019_18217_Handler()
        result = handler.check_trigger(
            "CWD",
            "../" * 20,
            None
        )
        assert result.triggered is True

    def test_trigger_on_long_path(self):
        """Test trigger on very long path."""
        handler = CVE_2019_18217_Handler()
        result = handler.check_trigger(
            "CWD",
            "A" * 5000,
            None
        )
        assert result.triggered is True
        assert result.should_crash is True


class TestCVE_2022_34977:
    """Tests for MLSD overflow CVE."""

    def test_trigger_on_long_mlsd_arg(self):
        """Test trigger on long MLSD argument."""
        handler = CVE_2022_34977_Handler()
        result = handler.check_trigger(
            "MLSD",
            "A" * 1000,
            None
        )
        assert result.triggered is True

    def test_crash_on_very_long_arg(self):
        """Test crash on very long MLSD argument."""
        handler = CVE_2022_34977_Handler()
        result = handler.check_trigger(
            "MLSD",
            "A" * 3000,
            None
        )
        assert result.should_crash is True


class TestCVESeverity:
    """Tests for CVE severity levels."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert CVESeverity.LOW.value == "low"
        assert CVESeverity.MEDIUM.value == "medium"
        assert CVESeverity.HIGH.value == "high"
        assert CVESeverity.CRITICAL.value == "critical"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
