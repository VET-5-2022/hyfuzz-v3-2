#!/usr/bin/env python3
"""
HyFuzz v3 - FTP Protocol Fuzzing Framework
Main entry point for running fuzzing experiments.

This framework supports ablation study with 5 different fuzzer configurations:
1. Baseline (pure boofuzz)
2. LLM Seed (LLM for seeds, boofuzz for mutation)
3. LLM Mutation (boofuzz for seeds, LLM for mutation)
4. LLM Full (LLM for both seeds and mutation)
5. Feedback (boofuzz with LLM-adjusted strategy)
"""
import argparse
import logging
import sys
import time
import json
from pathlib import Path
from datetime import datetime

from config.settings import Settings, get_settings
from target.vulnerable_ftp_server import VulnerableFTPServer
from target.server_manager import ServerManager, ServerState
from target.crash_logger import CrashLogger
from fuzzer.base_fuzzer import FuzzerConfig, FuzzerType
from fuzzer.baseline_boofuzz import BaselineBoofuzzFuzzer
from fuzzer.llm_seed_fuzzer import LLMSeedFuzzer
from fuzzer.llm_mutation_fuzzer import LLMMutationFuzzer
from fuzzer.llm_full_fuzzer import LLMFullFuzzer
from fuzzer.feedback_fuzzer import FeedbackFuzzer
from utils.metrics import MetricsCollector
from utils.logger import setup_logging


def create_fuzzer(fuzzer_type: str, config: FuzzerConfig, metrics: MetricsCollector, settings: Settings):
    """Create a fuzzer instance based on type."""
    ollama_host = settings.ollama.host
    seed_model = settings.ollama.seed_model
    mutation_model = settings.ollama.mutation_model

    if fuzzer_type == "baseline":
        return BaselineBoofuzzFuzzer(config, metrics)

    elif fuzzer_type == "llm_seed":
        return LLMSeedFuzzer(
            config, metrics,
            ollama_host=ollama_host,
            seed_model=seed_model
        )

    elif fuzzer_type == "llm_mutation":
        return LLMMutationFuzzer(
            config, metrics,
            ollama_host=ollama_host,
            mutation_model=mutation_model
        )

    elif fuzzer_type == "llm_full":
        return LLMFullFuzzer(
            config, metrics,
            ollama_host=ollama_host,
            seed_model=seed_model,
            mutation_model=mutation_model
        )

    elif fuzzer_type == "feedback":
        return FeedbackFuzzer(
            config, metrics,
            ollama_host=ollama_host,
            strategy_model=mutation_model
        )

    else:
        raise ValueError(f"Unknown fuzzer type: {fuzzer_type}")


def run_single_fuzzer(args, settings: Settings):
    """Run a single fuzzer type."""
    setup_logging(settings.metrics.log_level, settings.metrics.log_file)

    # Create FTP server
    logging.info("Starting vulnerable FTP server...")
    server = VulnerableFTPServer(
        host=settings.ftp_server.host,
        port=settings.ftp_server.port,
        root_dir=settings.ftp_server.root_dir,
        crash_log_dir=settings.ftp_server.crash_log_dir,
    )

    # Create server manager for auto-restart
    manager = ServerManager(
        server,
        restart_delay=settings.ftp_server.restart_delay,
    )

    # Start server
    manager.start()
    if not manager.wait_for_ready(timeout=10):
        logging.error("Server failed to start")
        return

    logging.info(f"FTP server running on {settings.ftp_server.host}:{settings.ftp_server.port}")

    # Create metrics collector
    metrics = MetricsCollector(settings.fuzzer.results_dir)

    # Create fuzzer config
    fuzzer_config = FuzzerConfig(
        target_host=settings.fuzzer.target_host,
        target_port=settings.fuzzer.target_port,
        timeout=settings.fuzzer.timeout,
        max_iterations=args.iterations,
    )

    # Create and run fuzzer
    fuzzer = create_fuzzer(args.fuzzer, fuzzer_config, metrics, settings)
    manager.set_fuzzer_context(fuzzer.fuzzer_type.value, fuzzer.session_id)

    logging.info(f"Starting {args.fuzzer} fuzzer for {args.iterations} iterations...")

    try:
        results = fuzzer.run(args.iterations)

        # End metrics session and display results
        metrics.end_session(args.fuzzer, fuzzer.session_id)

        # Display results table
        print()
        metrics.display_results_table(f"Fuzzing Results - {args.fuzzer}")
        print()

        # Display CVE breakdown if any CVEs triggered
        metrics.display_cve_breakdown_table("CVE Trigger Details")
        print()

        # Display timing metrics
        metrics.display_timing_table("Timing Metrics")
        print()

        # Save full report
        report = metrics.generate_comparison_report()
        results_file = Path(settings.fuzzer.results_dir) / f"{args.fuzzer}_results.json"
        with open(results_file, 'w') as f:
            json.dump(report, f, indent=2)
        logging.info(f"Results saved to {results_file}")

    except KeyboardInterrupt:
        logging.info("Fuzzing interrupted by user")
        # Still save partial results
        metrics.end_session(args.fuzzer, fuzzer.session_id)
        report = metrics.generate_comparison_report()
        results_file = Path(settings.fuzzer.results_dir) / f"{args.fuzzer}_partial_results.json"
        with open(results_file, 'w') as f:
            json.dump(report, f, indent=2)

    finally:
        manager.stop()


def run_ablation_study(args, settings: Settings):
    """Run complete ablation study with all fuzzer variants."""
    setup_logging(settings.metrics.log_level, settings.metrics.log_file)

    fuzzer_types = ["baseline", "llm_seed", "llm_mutation", "llm_full", "feedback"]

    logging.info("=" * 60)
    logging.info("ABLATION STUDY - FTP FUZZING")
    logging.info("=" * 60)
    logging.info(f"Iterations per fuzzer: {args.iterations}")
    logging.info(f"Fuzzer variants: {', '.join(fuzzer_types)}")
    logging.info("=" * 60)

    # Create shared metrics collector
    metrics = MetricsCollector(settings.fuzzer.results_dir)

    for fuzzer_type in fuzzer_types:
        logging.info(f"\n{'=' * 40}")
        logging.info(f"Running: {fuzzer_type.upper()}")
        logging.info(f"{'=' * 40}")

        # Create fresh server for each fuzzer
        server = VulnerableFTPServer(
            host=settings.ftp_server.host,
            port=settings.ftp_server.port,
            root_dir=f"{settings.ftp_server.root_dir}_{fuzzer_type}",
            crash_log_dir=f"{settings.ftp_server.crash_log_dir}/{fuzzer_type}",
        )

        manager = ServerManager(server, restart_delay=settings.ftp_server.restart_delay)
        manager.start()

        if not manager.wait_for_ready(timeout=10):
            logging.error(f"Server failed to start for {fuzzer_type}")
            continue

        # Create fuzzer
        fuzzer_config = FuzzerConfig(
            target_host=settings.fuzzer.target_host,
            target_port=settings.fuzzer.target_port,
            timeout=settings.fuzzer.timeout,
            max_iterations=args.iterations,
        )

        fuzzer = create_fuzzer(fuzzer_type, fuzzer_config, metrics, settings)
        manager.set_fuzzer_context(fuzzer.fuzzer_type.value, fuzzer.session_id)

        try:
            results = fuzzer.run(args.iterations)

            # End session to finalize metrics
            metrics.end_session(fuzzer_type, fuzzer.session_id)

            m = metrics.get_metrics(fuzzer_type, fuzzer.session_id)
            if m:
                logging.info(f"Completed {fuzzer_type}: {m.crashes_found} crashes, {len(m.cve_triggers)} CVEs")

        except Exception as e:
            logging.error(f"Error running {fuzzer_type}: {e}")
            # Still end session to capture partial data
            metrics.end_session(fuzzer_type, fuzzer.session_id)

        finally:
            manager.stop()
            time.sleep(2)  # Brief pause between fuzzers

    # Display full report with rich tables
    print("\n")
    metrics.display_full_report()

    # Save ablation study results
    report = metrics.generate_comparison_report()

    report_file = Path(settings.fuzzer.results_dir) / "ablation_study_results.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    logging.info(f"Full report saved to: {report_file}")

    # Export CSV
    csv_file = metrics.export_csv()
    logging.info(f"Metrics exported to: {csv_file}")


def run_server_only(args, settings: Settings):
    """Run only the vulnerable FTP server (for manual testing)."""
    setup_logging(settings.metrics.log_level)

    logging.info("Starting vulnerable FTP server in standalone mode...")

    server = VulnerableFTPServer(
        host=settings.ftp_server.host,
        port=settings.ftp_server.port,
        root_dir=settings.ftp_server.root_dir,
        crash_log_dir=settings.ftp_server.crash_log_dir,
    )

    manager = ServerManager(server, restart_delay=settings.ftp_server.restart_delay)
    manager.start()

    logging.info(f"FTP server running on {settings.ftp_server.host}:{settings.ftp_server.port}")
    logging.info("Press Ctrl+C to stop")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
        manager.stop()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="HyFuzz v3 - FTP Protocol Fuzzing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run baseline boofuzz fuzzer
  python main.py --fuzzer baseline --iterations 1000

  # Run LLM seed generation fuzzer
  python main.py --fuzzer llm_seed --iterations 1000

  # Run complete ablation study
  python main.py --ablation --iterations 500

  # Run only the vulnerable FTP server
  python main.py --server-only

Fuzzer Types:
  baseline      Pure boofuzz (control group)
  llm_seed      LLM for seed generation, boofuzz for mutation
  llm_mutation  Boofuzz for seeds, LLM for mutation
  llm_full      LLM for both seeds and mutation
  feedback      Boofuzz with LLM-adjusted strategy based on feedback
        """
    )

    parser.add_argument(
        "--fuzzer", "-f",
        choices=["baseline", "llm_seed", "llm_mutation", "llm_full", "feedback"],
        default="baseline",
        help="Type of fuzzer to run"
    )

    parser.add_argument(
        "--iterations", "-i",
        type=int,
        default=1000,
        help="Number of fuzzing iterations (default: 1000)"
    )

    parser.add_argument(
        "--ablation", "-a",
        action="store_true",
        help="Run complete ablation study with all fuzzer variants"
    )

    parser.add_argument(
        "--server-only", "-s",
        action="store_true",
        help="Run only the vulnerable FTP server"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="FTP server host (default: 127.0.0.1)"
    )

    parser.add_argument(
        "--port", "-p",
        type=int,
        default=2121,
        help="FTP server port (default: 2121)"
    )

    parser.add_argument(
        "--ollama-host",
        default="http://localhost:11434",
        help="Ollama server URL (default: http://localhost:11434)"
    )

    parser.add_argument(
        "--seed-model",
        default="qwen3:8b",
        help="LLM model for seed generation (default: qwen3:8b)"
    )

    parser.add_argument(
        "--mutation-model",
        default="qwen3:8b",
        help="LLM model for mutation (default: qwen3:8b)"
    )

    parser.add_argument(
        "--results-dir",
        default="./results",
        help="Directory for results output (default: ./results)"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Load settings
    settings = get_settings()

    # Override settings from args
    settings.ftp_server.host = args.host
    settings.ftp_server.port = args.port
    settings.fuzzer.target_host = args.host
    settings.fuzzer.target_port = args.port
    settings.ollama.host = args.ollama_host
    settings.ollama.seed_model = args.seed_model
    settings.ollama.mutation_model = args.mutation_model
    settings.fuzzer.results_dir = args.results_dir

    if args.verbose:
        settings.metrics.log_level = "DEBUG"

    # Run appropriate mode
    if args.server_only:
        run_server_only(args, settings)
    elif args.ablation:
        run_ablation_study(args, settings)
    else:
        run_single_fuzzer(args, settings)


if __name__ == "__main__":
    main()
