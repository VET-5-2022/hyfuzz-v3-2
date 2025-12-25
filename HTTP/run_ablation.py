#!/usr/bin/env python3
"""
Ablation Study Runner

Main entry point for running the HTTP fuzzing ablation study.
Compares five fuzzer variants:
1. boofuzz_baseline - Standard boofuzz fuzzing
2. llm_seed - LLM for seed generation, boofuzz for mutation
3. llm_mutation - Boofuzz for seeds, LLM for mutation
4. llm_full - LLM for both seed and mutation
5. llm_feedback - Boofuzz with LLM-guided strategy adjustment
"""

import os
import sys
import json
import time
import argparse
import signal
from datetime import datetime
from dataclasses import asdict
from typing import Dict, Any, List, Optional

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.helpers import load_config, setup_logging, ensure_dir
from target.supervisor import ServerSupervisor
from target.crash_logger import CrashLogger
from fuzzer.boofuzz_baseline import BoofuzzBaseline
from fuzzer.llm_seed_fuzzer import LLMSeedFuzzer
from fuzzer.llm_mutation_fuzzer import LLMMutationFuzzer
from fuzzer.llm_full_fuzzer import LLMFullFuzzer
from fuzzer.llm_feedback_fuzzer import LLMFeedbackFuzzer
from fuzzer.base_fuzzer import FuzzingResult
from fuzzer.llm_client import OllamaClient


class AblationStudy:
    """
    Manages the ablation study comparing different fuzzer variants.
    """

    FUZZER_VARIANTS = {
        "boofuzz_baseline": BoofuzzBaseline,
        "llm_seed": LLMSeedFuzzer,
        "llm_mutation": LLMMutationFuzzer,
        "llm_full": LLMFullFuzzer,
        "llm_feedback": LLMFeedbackFuzzer,
    }

    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize the ablation study.

        Args:
            config_path: Path to configuration file
        """
        self.config = load_config(config_path)
        self.logger = setup_logging("AblationStudy", self.config["logging"]["log_level"])

        # Results storage
        self.results: Dict[str, FuzzingResult] = {}
        self.study_start_time: Optional[datetime] = None
        self.study_end_time: Optional[datetime] = None

        # Components
        self.crash_logger: Optional[CrashLogger] = None
        self.supervisor: Optional[ServerSupervisor] = None

        # Session ID for this study run
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Ensure directories exist
        ensure_dir(self.config["ablation"]["results_dir"])
        ensure_dir(self.config["logging"]["crash_log_dir"])
        ensure_dir(self.config["logging"]["cve_log_dir"])

    def setup_target(self):
        """Set up the target server with supervisor."""
        self.logger.info("Setting up target server...")

        self.crash_logger = CrashLogger(
            crash_log_dir=self.config["logging"]["crash_log_dir"],
            cve_log_dir=self.config["logging"]["cve_log_dir"]
        )

        self.supervisor = ServerSupervisor(
            host=self.config["target"]["host"],
            port=self.config["target"]["port"],
            restart_delay=self.config["target"]["restart_delay"],
            max_restarts=self.config["target"]["max_restarts"],
            crash_logger=self.crash_logger,
            simulate_crashes=True
        )

        self.supervisor.start()
        time.sleep(1)  # Wait for server to start

        if not self.supervisor.is_running():
            raise RuntimeError("Failed to start target server")

        self.logger.info(f"Target server running on {self.config['target']['host']}:{self.config['target']['port']}")

    def teardown_target(self):
        """Shut down the target server."""
        if self.supervisor:
            self.logger.info("Shutting down target server...")
            self.supervisor.stop()

    def get_fuzzer_kwargs(self) -> Dict[str, Any]:
        """Get common kwargs for fuzzer initialization."""
        return {
            "target_host": self.config["target"]["host"],
            "target_port": self.config["target"]["port"],
            "connection_timeout": self.config["fuzzer"]["connection_timeout"],
            "recv_timeout": self.config["fuzzer"]["recv_timeout"],
            "max_iterations": self.config["ablation"]["iterations_per_variant"],
            "log_level": self.config["logging"]["log_level"],
        }

    def get_llm_kwargs(self) -> Dict[str, Any]:
        """Get LLM-specific kwargs."""
        return {
            "llm_base_url": self.config["llm"]["base_url"],
            "llm_model": self.config["llm"]["model"],
            "llm_timeout": self.config["llm"]["timeout"],
            "llm_temperature": self.config["llm"]["temperature"],
        }

    def warmup_llm(self) -> bool:
        """
        Warm up the LLM model before starting fuzzing.
        This ensures the model is loaded into memory.

        Returns:
            True if warmup successful
        """
        self.logger.info("Warming up LLM model...")

        client = OllamaClient(
            base_url=self.config["llm"]["base_url"],
            model=self.config["llm"]["model"],
            timeout=self.config["llm"]["timeout"],
        )

        # Check if Ollama is available
        if not client.is_available():
            self.logger.error("Ollama is not available or model not found")
            return False

        # Warmup the model
        return client.warmup()

    def run_variant(self, variant_name: str, iterations: int) -> FuzzingResult:
        """
        Run a single fuzzer variant.

        Args:
            variant_name: Name of the fuzzer variant
            iterations: Number of iterations to run

        Returns:
            FuzzingResult with statistics
        """
        self.logger.info(f"{'='*60}")
        self.logger.info(f"Running variant: {variant_name}")
        self.logger.info(f"Iterations: {iterations}")
        self.logger.info(f"{'='*60}")

        # Set the fuzzer variant in supervisor for logging
        if self.supervisor:
            self.supervisor.set_fuzzer_variant(variant_name)
            self.supervisor.reset_restart_count()

        # Get the fuzzer class
        fuzzer_class = self.FUZZER_VARIANTS.get(variant_name)
        if not fuzzer_class:
            raise ValueError(f"Unknown fuzzer variant: {variant_name}")

        # Initialize fuzzer with appropriate kwargs
        kwargs = self.get_fuzzer_kwargs()

        # Add LLM kwargs for LLM-based variants
        if variant_name in ["llm_seed", "llm_mutation", "llm_full", "llm_feedback"]:
            kwargs.update(self.get_llm_kwargs())

        fuzzer = fuzzer_class(**kwargs)

        # Run the fuzzer
        result = fuzzer.run(iterations=iterations)

        # Add supervisor stats
        if self.supervisor:
            result.coverage_metrics["server_restarts"] = self.supervisor.get_status()["total_restarts"]

        self.logger.info(f"Variant {variant_name} completed:")
        self.logger.info(f"  - Crashes: {result.crashes_found}")
        self.logger.info(f"  - CVE triggers: {result.total_cve_triggers}")
        self.logger.info(f"  - Duration: {result.duration_seconds:.2f}s")
        self.logger.info(f"  - RPS: {result.requests_per_second:.2f}")

        return result

    def run_study(
        self,
        variants: Optional[List[str]] = None,
        iterations: Optional[int] = None
    ):
        """
        Run the full ablation study.

        Args:
            variants: List of variants to test (default: all)
            iterations: Iterations per variant (default: from config)
        """
        self.study_start_time = datetime.now()

        if variants is None:
            variants = self.config["ablation"]["variants"]

        if iterations is None:
            iterations = self.config["ablation"]["iterations_per_variant"]

        self.logger.info("="*70)
        self.logger.info("ABLATION STUDY STARTING")
        self.logger.info(f"Session ID: {self.session_id}")
        self.logger.info(f"Variants: {variants}")
        self.logger.info(f"Iterations per variant: {iterations}")
        self.logger.info("="*70)

        try:
            # Set up target server
            self.setup_target()

            # Warm up LLM if any LLM variants will be run
            llm_variants = ["llm_seed", "llm_mutation", "llm_full", "llm_feedback"]
            if any(v in llm_variants for v in variants):
                if not self.warmup_llm():
                    self.logger.warning("LLM warmup failed, LLM variants may timeout")

            # Run each variant
            for variant in variants:
                try:
                    result = self.run_variant(variant, iterations)
                    self.results[variant] = result

                    # Save intermediate results
                    self._save_results()

                    # Brief pause between variants
                    time.sleep(2)

                except Exception as e:
                    self.logger.error(f"Error running variant {variant}: {e}")
                    continue

            self.study_end_time = datetime.now()

            # Generate final report
            self._generate_report()

        finally:
            self.teardown_target()

    def _save_results(self):
        """Save current results to file."""
        results_file = os.path.join(
            self.config["ablation"]["results_dir"],
            f"ablation_results_{self.session_id}.json"
        )

        data = {
            "session_id": self.session_id,
            "start_time": self.study_start_time.isoformat() if self.study_start_time else None,
            "end_time": self.study_end_time.isoformat() if self.study_end_time else None,
            "results": {
                name: asdict(result)
                for name, result in self.results.items()
            }
        }

        with open(results_file, 'w') as f:
            json.dump(data, f, indent=2)

        self.logger.info(f"Results saved to {results_file}")

    def _generate_report(self):
        """Generate the comprehensive ablation study report."""
        self.logger.info("\n" + "="*80)
        self.logger.info("ABLATION STUDY RESULTS")
        self.logger.info("="*80)

        # ============ Table 1: Basic Metrics ============
        print("\n" + "="*80)
        print("TABLE 1: BASIC METRICS")
        print("="*80)
        print("{:<18} {:>10} {:>10} {:>12} {:>10} {:>12}".format(
            "Variant", "Iterations", "Crashes", "CVE Hits", "Duration", "Exec Rate"
        ))
        print("-" * 80)

        for name, result in self.results.items():
            print("{:<18} {:>10} {:>10} {:>12} {:>10.2f}s {:>10.2f}/s".format(
                name,
                result.total_iterations,
                result.crashes_found,
                result.total_cve_triggers,
                result.duration_seconds,
                result.execution_rate
            ))
        print("-" * 80)

        # ============ Table 2: Time-to-First Metrics ============
        print("\n" + "="*80)
        print("TABLE 2: TIME TO FIRST (TTF) METRICS")
        print("="*80)
        print("{:<18} {:>15} {:>15} {:>15} {:>15}".format(
            "Variant", "TTFC (s)", "TTF-CVE (s)", "Crash Rate", "CVE Rate"
        ))
        print("-" * 80)

        for name, result in self.results.items():
            ttfc = f"{result.time_to_first_crash:.2f}" if result.time_to_first_crash else "N/A"
            ttfcve = f"{result.time_to_first_cve:.2f}" if result.time_to_first_cve else "N/A"
            print("{:<18} {:>15} {:>15} {:>13.2f}/k {:>13.2f}/k".format(
                name,
                ttfc,
                ttfcve,
                result.crash_rate,
                result.cve_trigger_rate
            ))
        print("-" * 80)

        # ============ Table 3: Coverage Metrics ============
        print("\n" + "="*80)
        print("TABLE 3: COVERAGE METRICS")
        print("="*80)
        print("{:<18} {:>12} {:>12} {:>12} {:>15}".format(
            "Variant", "Uniq Paths", "Uniq Methods", "Status Codes", "CVE Coverage"
        ))
        print("-" * 80)

        for name, result in self.results.items():
            cve_coverage = f"{result.code_paths_covered}/10"  # out of 10 CVEs
            print("{:<18} {:>12} {:>12} {:>12} {:>15}".format(
                name,
                result.unique_paths_tested,
                result.unique_methods_tested,
                result.unique_status_codes,
                cve_coverage
            ))
        print("-" * 80)

        # ============ Table 4: CVE Breakdown ============
        print("\n" + "="*80)
        print("TABLE 4: CVE TRIGGERS BY VARIANT")
        print("="*80)

        all_cves = set()
        for result in self.results.values():
            all_cves.update(result.cve_triggers.keys())

        if all_cves:
            # Print header
            header = "{:<18}".format("Variant")
            for cve in sorted(all_cves):
                header += " {:>10}".format(cve[-8:])  # Last 8 chars of CVE
            print(header)
            print("-" * 80)

            for name, result in self.results.items():
                row = "{:<18}".format(name)
                for cve in sorted(all_cves):
                    count = result.cve_triggers.get(cve, 0)
                    row += " {:>10}".format(count)
                print(row)
            print("-" * 80)

        # ============ Save Detailed Report ============
        report_file = os.path.join(
            self.config["ablation"]["results_dir"],
            f"ablation_report_{self.session_id}.txt"
        )

        with open(report_file, 'w') as f:
            f.write("="*80 + "\n")
            f.write("HYFUZZ-V3 ABLATION STUDY REPORT\n")
            f.write("="*80 + "\n\n")

            f.write(f"Session ID: {self.session_id}\n")
            f.write(f"Start Time: {self.study_start_time}\n")
            f.write(f"End Time: {self.study_end_time}\n")

            if self.study_start_time and self.study_end_time:
                total_duration = (self.study_end_time - self.study_start_time).total_seconds()
                f.write(f"Total Duration: {total_duration:.2f}s\n")

            # Summary comparison table
            f.write("\n" + "="*80 + "\n")
            f.write("SUMMARY COMPARISON\n")
            f.write("="*80 + "\n\n")

            f.write("{:<18} {:>10} {:>10} {:>10} {:>10} {:>10}\n".format(
                "Metric", "baseline", "llm_seed", "llm_mut", "llm_full", "llm_fb"
            ))
            f.write("-" * 80 + "\n")

            # Get results in order
            variants_order = ["boofuzz_baseline", "llm_seed", "llm_mutation", "llm_full", "llm_feedback"]
            metrics_to_compare = [
                ("Exec Rate", lambda r: f"{r.execution_rate:.1f}"),
                ("Crashes", lambda r: str(r.crashes_found)),
                ("CVE Triggers", lambda r: str(r.total_cve_triggers)),
                ("CVE Coverage", lambda r: f"{r.code_paths_covered}/10"),
                ("TTFC (s)", lambda r: f"{r.time_to_first_crash:.1f}" if r.time_to_first_crash else "N/A"),
                ("TTF-CVE (s)", lambda r: f"{r.time_to_first_cve:.1f}" if r.time_to_first_cve else "N/A"),
                ("Duration (s)", lambda r: f"{r.duration_seconds:.1f}"),
                ("Crash Rate/k", lambda r: f"{r.crash_rate:.2f}"),
                ("CVE Rate/k", lambda r: f"{r.cve_trigger_rate:.2f}"),
            ]

            for metric_name, metric_func in metrics_to_compare:
                row = f"{metric_name:<18}"
                for variant in variants_order:
                    if variant in self.results:
                        row += f" {metric_func(self.results[variant]):>10}"
                    else:
                        row += f" {'N/A':>10}"
                f.write(row + "\n")

            # Detailed results by variant
            f.write("\n" + "="*80 + "\n")
            f.write("DETAILED RESULTS BY VARIANT\n")
            f.write("="*80 + "\n")

            for name, result in self.results.items():
                f.write(f"\n{name.upper()}\n")
                f.write("-" * len(name) + "\n")
                f.write(f"  Basic Metrics:\n")
                f.write(f"    - Iterations: {result.total_iterations}\n")
                f.write(f"    - Duration: {result.duration_seconds:.2f}s\n")
                f.write(f"    - Execution Rate: {result.execution_rate:.2f} iter/s\n")
                f.write(f"\n  Crash Metrics:\n")
                f.write(f"    - Total Crashes: {result.crashes_found}\n")
                f.write(f"    - Crash Rate: {result.crash_rate:.2f} per 1000 iterations\n")
                f.write(f"    - Time to First Crash: {result.time_to_first_crash:.2f}s\n" if result.time_to_first_crash else f"    - Time to First Crash: N/A\n")
                f.write(f"\n  CVE Trigger Metrics:\n")
                f.write(f"    - Total CVE Triggers: {result.total_cve_triggers}\n")
                f.write(f"    - CVE Trigger Rate: {result.cve_trigger_rate:.2f} per 1000 iterations\n")
                f.write(f"    - Time to First CVE: {result.time_to_first_cve:.2f}s\n" if result.time_to_first_cve else f"    - Time to First CVE: N/A\n")
                f.write(f"    - CVE Breakdown: {result.cve_triggers}\n")
                f.write(f"\n  Coverage Metrics:\n")
                f.write(f"    - Unique Paths Tested: {result.unique_paths_tested}\n")
                f.write(f"    - Unique Methods Tested: {result.unique_methods_tested}\n")
                f.write(f"    - Unique Status Codes: {result.unique_status_codes}\n")
                f.write(f"    - CVE Coverage: {result.code_paths_covered}/10\n")
                f.write(f"\n  Generation Metrics:\n")
                f.write(f"    - Seeds Generated: {result.seeds_generated}\n")
                f.write(f"    - Mutations Performed: {result.mutations_performed}\n")
                f.write(f"    - Errors: {result.error_count}\n")
                f.write(f"    - Timeouts: {result.timeout_count}\n")

        self.logger.info(f"Detailed report saved to {report_file}")

        # Also save CSV for easy analysis
        csv_file = os.path.join(
            self.config["ablation"]["results_dir"],
            f"ablation_metrics_{self.session_id}.csv"
        )

        with open(csv_file, 'w') as f:
            # Header
            f.write("variant,iterations,duration_s,exec_rate,crashes,crash_rate,cve_triggers,cve_rate,")
            f.write("ttfc_s,ttf_cve_s,unique_paths,unique_methods,cve_coverage\n")

            for name, result in self.results.items():
                ttfc = f"{result.time_to_first_crash:.2f}" if result.time_to_first_crash else ""
                ttfcve = f"{result.time_to_first_cve:.2f}" if result.time_to_first_cve else ""
                f.write(f"{name},{result.total_iterations},{result.duration_seconds:.2f},")
                f.write(f"{result.execution_rate:.2f},{result.crashes_found},{result.crash_rate:.2f},")
                f.write(f"{result.total_cve_triggers},{result.cve_trigger_rate:.2f},")
                f.write(f"{ttfc},{ttfcve},{result.unique_paths_tested},{result.unique_methods_tested},")
                f.write(f"{result.code_paths_covered}\n")

        self.logger.info(f"CSV metrics saved to {csv_file}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="HyFuzz HTTP Fuzzing Ablation Study"
    )
    parser.add_argument(
        "--config", "-c",
        default="config/config.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--variants", "-v",
        nargs="+",
        choices=list(AblationStudy.FUZZER_VARIANTS.keys()),
        help="Specific variants to run (default: all)"
    )
    parser.add_argument(
        "--iterations", "-i",
        type=int,
        help="Iterations per variant (overrides config)"
    )
    parser.add_argument(
        "--target-only",
        action="store_true",
        help="Only start the target server (for debugging)"
    )

    args = parser.parse_args()

    # Handle Ctrl+C gracefully
    study = None

    def signal_handler(signum, frame):
        print("\nInterrupted. Cleaning up...")
        if study:
            study.teardown_target()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    study = AblationStudy(config_path=args.config)

    if args.target_only:
        # Just run the target server
        study.setup_target()
        print(f"Target server running on {study.config['target']['host']}:{study.config['target']['port']}")
        print("Press Ctrl+C to stop")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            study.teardown_target()
    else:
        # Run the full ablation study
        study.run_study(
            variants=args.variants,
            iterations=args.iterations
        )


if __name__ == "__main__":
    main()
