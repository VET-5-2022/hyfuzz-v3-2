"""
Metrics collection and analysis for ablation study comparison.
Enhanced with comprehensive runtime tracking and rich table display.
"""
import json
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
import threading

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box


@dataclass
class FuzzerMetrics:
    """Metrics for a single fuzzer run."""
    # Basic info
    variant_name: str
    session_id: str
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0

    # Iteration metrics
    total_iterations: int = 0
    successful_iterations: int = 0
    failed_iterations: int = 0

    # Crash metrics
    crashes_found: int = 0
    unique_crashes: int = 0
    crash_hashes: Set[str] = field(default_factory=set)

    # CVE tracking - detailed breakdown
    cve_triggers: Dict[str, int] = field(default_factory=dict)  # CVE -> total count
    unique_cve_triggers: Dict[str, int] = field(default_factory=dict)  # CVE -> unique count
    total_cve_triggers: int = 0
    cve_first_trigger_times: Dict[str, float] = field(default_factory=dict)  # CVE -> seconds since start
    unique_cve_payloads: Dict[str, Set[str]] = field(default_factory=dict)  # CVE -> set of payload hashes

    # Timing metrics
    time_to_first_crash: Optional[float] = None
    time_to_first_cve: Optional[float] = None

    # Performance metrics
    requests_per_second: float = 0.0
    execution_rate: float = 0.0
    crash_rate: float = 0.0
    cve_trigger_rate: float = 0.0
    avg_response_time_ms: float = 0.0
    total_response_times: List[float] = field(default_factory=list)

    # Error tracking
    error_count: int = 0
    timeout_count: int = 0
    connection_errors: int = 0

    # Seed metrics
    seeds_generated: int = 0
    seeds_from_llm: int = 0
    seeds_from_boofuzz: int = 0

    # Mutation metrics
    mutations_performed: int = 0
    mutations_from_llm: int = 0
    mutations_from_boofuzz: int = 0
    mutation_types: Dict[str, int] = field(default_factory=dict)

    # Coverage metrics
    unique_paths_tested: int = 0
    unique_methods_tested: int = 0
    unique_status_codes: int = 0
    code_paths_covered: int = 0
    _tested_paths: Set[str] = field(default_factory=set)
    _tested_methods: Set[str] = field(default_factory=set)
    _status_codes_seen: Set[int] = field(default_factory=set)

    # LLM metrics (for LLM-based fuzzers)
    llm_requests: int = 0
    llm_tokens_used: int = 0
    llm_avg_latency_ms: float = 0.0
    llm_latencies: List[float] = field(default_factory=list)

    # Server metrics
    server_restarts: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            "variant_name": self.variant_name,
            "total_iterations": self.total_iterations,
            "crashes_found": self.crashes_found,
            "unique_crashes": self.unique_crashes,
            "cve_triggers": self.cve_triggers,
            "unique_cve_triggers": self.unique_cve_triggers,
            "total_cve_triggers": self.total_cve_triggers,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "requests_per_second": self.requests_per_second,
            "seeds_generated": self.seeds_generated,
            "mutations_performed": self.mutations_performed,
            "coverage_metrics": {
                "server_restarts": self.server_restarts,
            },
            "error_count": self.error_count,
            "timeout_count": self.timeout_count,
            "time_to_first_crash": self.time_to_first_crash,
            "time_to_first_cve": self.time_to_first_cve,
            "execution_rate": self.execution_rate,
            "crash_rate": self.crash_rate,
            "cve_trigger_rate": self.cve_trigger_rate,
            "unique_paths_tested": self.unique_paths_tested,
            "unique_methods_tested": self.unique_methods_tested,
            "unique_status_codes": self.unique_status_codes,
            "code_paths_covered": self.code_paths_covered,
            "llm_requests": self.llm_requests,
            "llm_tokens_used": self.llm_tokens_used,
            "llm_avg_latency_ms": self.llm_avg_latency_ms,
        }
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FuzzerMetrics":
        """Create from dictionary."""
        # Handle subset of fields
        known_fields = {
            'variant_name', 'session_id', 'start_time', 'end_time',
            'duration_seconds', 'total_iterations', 'crashes_found',
            'unique_crashes', 'cve_triggers', 'unique_cve_triggers',
            'total_cve_triggers', 'time_to_first_crash', 'time_to_first_cve',
            'requests_per_second', 'seeds_generated', 'mutations_performed',
            'error_count', 'timeout_count'
        }
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered)

    def calculate_derived_metrics(self):
        """Calculate derived metrics from raw data."""
        if self.duration_seconds > 0:
            self.requests_per_second = self.total_iterations / self.duration_seconds
            self.execution_rate = self.requests_per_second
            # Rates per 1000 iterations
            self.crash_rate = (self.crashes_found / self.total_iterations) * 1000 if self.total_iterations > 0 else 0
            self.cve_trigger_rate = (self.total_cve_triggers / self.total_iterations) * 1000 if self.total_iterations > 0 else 0

        if self.total_response_times:
            self.avg_response_time_ms = sum(self.total_response_times) / len(self.total_response_times)

        if self.llm_latencies:
            self.llm_avg_latency_ms = sum(self.llm_latencies) / len(self.llm_latencies)

        # Update coverage counts
        self.unique_paths_tested = len(self._tested_paths)
        self.unique_methods_tested = len(self._tested_methods)
        self.unique_status_codes = len(self._status_codes_seen)


class MetricsCollector:
    """
    Collects and manages metrics for fuzzing sessions.
    Supports real-time metrics collection and ablation study comparison.
    """

    def __init__(self, results_dir: str = "./results"):
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self._metrics: Dict[str, FuzzerMetrics] = {}
        self._lock = threading.Lock()
        self._session_start_times: Dict[str, float] = {}
        self._console = Console()

    def start_session(self, fuzzer_type: str, session_id: str) -> FuzzerMetrics:
        """Start a new metrics collection session."""
        with self._lock:
            key = f"{fuzzer_type}_{session_id}"

            metrics = FuzzerMetrics(
                variant_name=fuzzer_type,
                session_id=session_id,
                start_time=datetime.now().isoformat(),
            )

            self._metrics[key] = metrics
            self._session_start_times[key] = time.time()

            return metrics

    def get_metrics(self, fuzzer_type: str, session_id: str) -> Optional[FuzzerMetrics]:
        """Get metrics for a session."""
        key = f"{fuzzer_type}_{session_id}"
        return self._metrics.get(key)

    def record_iteration(
        self,
        fuzzer_type: str,
        session_id: str,
        success: bool = True,
        response_time_ms: float = 0.0,
        method: str = None,
        path: str = None,
        status_code: int = None,
    ):
        """Record an iteration with optional coverage info."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return

            metrics = self._metrics[key]
            metrics.total_iterations += 1

            if success:
                metrics.successful_iterations += 1
            else:
                metrics.failed_iterations += 1

            if response_time_ms > 0:
                metrics.total_response_times.append(response_time_ms)

            # Track coverage
            if method:
                metrics._tested_methods.add(method)
            if path:
                metrics._tested_paths.add(path)
            if status_code is not None:
                metrics._status_codes_seen.add(status_code)

    def record_crash(
        self,
        fuzzer_type: str,
        session_id: str,
        crash_hash: str = None,
        cve_id: Optional[str] = None,
        payload_hash: str = None,
    ):
        """Record a crash event with optional CVE association."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return

            metrics = self._metrics[key]
            metrics.crashes_found += 1

            # Time to first crash
            if metrics.time_to_first_crash is None:
                metrics.time_to_first_crash = time.time() - self._session_start_times[key]

            # Track unique crashes
            if crash_hash and crash_hash not in metrics.crash_hashes:
                metrics.crash_hashes.add(crash_hash)
                metrics.unique_crashes += 1

            # Track CVE triggers
            if cve_id:
                # Total triggers per CVE
                metrics.cve_triggers[cve_id] = metrics.cve_triggers.get(cve_id, 0) + 1
                metrics.total_cve_triggers += 1

                # Time to first CVE
                if metrics.time_to_first_cve is None:
                    metrics.time_to_first_cve = time.time() - self._session_start_times[key]

                # First trigger time for this specific CVE
                if cve_id not in metrics.cve_first_trigger_times:
                    metrics.cve_first_trigger_times[cve_id] = time.time() - self._session_start_times[key]

                # Track unique payloads per CVE
                if payload_hash:
                    if cve_id not in metrics.unique_cve_payloads:
                        metrics.unique_cve_payloads[cve_id] = set()

                    if payload_hash not in metrics.unique_cve_payloads[cve_id]:
                        metrics.unique_cve_payloads[cve_id].add(payload_hash)
                        metrics.unique_cve_triggers[cve_id] = metrics.unique_cve_triggers.get(cve_id, 0) + 1

    def record_error(
        self,
        fuzzer_type: str,
        session_id: str,
        error_type: str = "general",
    ):
        """Record an error event."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return

            metrics = self._metrics[key]
            if error_type == "timeout":
                metrics.timeout_count += 1
            elif error_type == "connection":
                metrics.connection_errors += 1
            else:
                metrics.error_count += 1

    def record_llm_request(
        self,
        fuzzer_type: str,
        session_id: str,
        tokens: int = 0,
        latency_ms: float = 0.0,
    ):
        """Record an LLM API request."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return

            metrics = self._metrics[key]
            metrics.llm_requests += 1
            # Handle None tokens
            if tokens is not None:
                metrics.llm_tokens_used += tokens

            if latency_ms and latency_ms > 0:
                metrics.llm_latencies.append(latency_ms)

    def record_seed_generation(
        self,
        fuzzer_type: str,
        session_id: str,
        count: int = 1,
        from_llm: bool = False,
    ):
        """Record seed generation."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return

            metrics = self._metrics[key]
            metrics.seeds_generated += count

            if from_llm:
                metrics.seeds_from_llm += count
            else:
                metrics.seeds_from_boofuzz += count

    def record_mutation(
        self,
        fuzzer_type: str,
        session_id: str,
        mutation_type: str,
        from_llm: bool = False,
    ):
        """Record a mutation operation."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return

            metrics = self._metrics[key]
            metrics.mutations_performed += 1

            if from_llm:
                metrics.mutations_from_llm += 1
            else:
                metrics.mutations_from_boofuzz += 1

            metrics.mutation_types[mutation_type] = metrics.mutation_types.get(mutation_type, 0) + 1

    def record_server_restart(self, fuzzer_type: str, session_id: str):
        """Record a server restart event."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return
            self._metrics[key].server_restarts += 1

    def record_code_path(self, fuzzer_type: str, session_id: str, path_id: str):
        """Record code path coverage."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return
            metrics = self._metrics[key]
            metrics._tested_paths.add(path_id)
            metrics.code_paths_covered = len(metrics._tested_paths)

    def end_session(self, fuzzer_type: str, session_id: str) -> FuzzerMetrics:
        """End a metrics collection session."""
        key = f"{fuzzer_type}_{session_id}"
        with self._lock:
            if key not in self._metrics:
                return None

            metrics = self._metrics[key]
            metrics.end_time = datetime.now().isoformat()
            metrics.duration_seconds = time.time() - self._session_start_times[key]
            metrics.calculate_derived_metrics()

            # Save to file
            self._save_metrics(metrics)

            return metrics

    def _save_metrics(self, metrics: FuzzerMetrics):
        """Save metrics to file."""
        filename = f"{metrics.variant_name}_{metrics.session_id}.json"
        filepath = self.results_dir / filename

        data = metrics.to_dict()

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def display_results_table(self, title: str = "Fuzzing Results"):
        """Display results as a rich table."""
        table = Table(
            title=title,
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
        )

        # Add columns
        table.add_column("Fuzzer", style="cyan", width=15)
        table.add_column("Iterations", justify="right", style="green")
        table.add_column("Crashes", justify="right", style="red")
        table.add_column("Unique", justify="right", style="red")
        table.add_column("CVE Triggers", justify="right", style="yellow")
        table.add_column("Unique CVEs", justify="right", style="yellow")
        table.add_column("Duration(s)", justify="right")
        table.add_column("Rate(req/s)", justify="right", style="blue")
        table.add_column("Errors", justify="right", style="dim")
        table.add_column("Timeouts", justify="right", style="dim")

        # Add rows for each fuzzer
        for key, metrics in self._metrics.items():
            metrics.calculate_derived_metrics()
            unique_cves = len(metrics.cve_triggers)

            table.add_row(
                metrics.variant_name,
                str(metrics.total_iterations),
                str(metrics.crashes_found),
                str(metrics.unique_crashes),
                str(metrics.total_cve_triggers),
                str(unique_cves),
                f"{metrics.duration_seconds:.1f}",
                f"{metrics.requests_per_second:.2f}",
                str(metrics.error_count),
                str(metrics.timeout_count),
            )

        self._console.print(table)

    def display_cve_breakdown_table(self, title: str = "CVE Trigger Breakdown"):
        """Display CVE breakdown per fuzzer."""
        # Collect all CVEs
        all_cves = set()
        for metrics in self._metrics.values():
            all_cves.update(metrics.cve_triggers.keys())

        if not all_cves:
            self._console.print("[yellow]No CVEs triggered[/yellow]")
            return

        table = Table(
            title=title,
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
        )

        # Add columns
        table.add_column("CVE ID", style="yellow", width=18)
        for key, metrics in self._metrics.items():
            table.add_column(metrics.variant_name, justify="right")

        # Add rows for each CVE
        for cve_id in sorted(all_cves):
            row = [cve_id]
            for metrics in self._metrics.values():
                total = metrics.cve_triggers.get(cve_id, 0)
                unique = metrics.unique_cve_triggers.get(cve_id, 0)
                row.append(f"{total} ({unique})")
            table.add_row(*row)

        # Add totals row
        table.add_row(
            "[bold]TOTAL[/bold]",
            *[f"[bold]{m.total_cve_triggers}[/bold]" for m in self._metrics.values()]
        )

        self._console.print(table)

    def display_timing_table(self, title: str = "Timing Metrics"):
        """Display timing metrics table."""
        table = Table(
            title=title,
            box=box.ROUNDED,
            show_header=True,
            header_style="bold green",
        )

        table.add_column("Fuzzer", style="cyan", width=15)
        table.add_column("Time to 1st Crash", justify="right")
        table.add_column("Time to 1st CVE", justify="right")
        table.add_column("Avg Response(ms)", justify="right")
        table.add_column("LLM Requests", justify="right")
        table.add_column("LLM Latency(ms)", justify="right")

        for metrics in self._metrics.values():
            metrics.calculate_derived_metrics()
            ttfc = f"{metrics.time_to_first_crash:.2f}s" if metrics.time_to_first_crash else "N/A"
            ttfcve = f"{metrics.time_to_first_cve:.2f}s" if metrics.time_to_first_cve else "N/A"

            table.add_row(
                metrics.variant_name,
                ttfc,
                ttfcve,
                f"{metrics.avg_response_time_ms:.2f}",
                str(metrics.llm_requests),
                f"{metrics.llm_avg_latency_ms:.2f}" if metrics.llm_avg_latency_ms > 0 else "N/A",
            )

        self._console.print(table)

    def display_full_report(self):
        """Display complete ablation study report with all tables."""
        self._console.print()
        self._console.print(Panel.fit(
            "[bold blue]ABLATION STUDY - FUZZING RESULTS[/bold blue]",
            border_style="blue"
        ))
        self._console.print()

        # Main results table
        self.display_results_table("Overall Results")
        self._console.print()

        # CVE breakdown
        self.display_cve_breakdown_table("CVE Trigger Breakdown (Total / Unique)")
        self._console.print()

        # Timing metrics
        self.display_timing_table("Timing & Performance Metrics")
        self._console.print()

    def generate_comparison_report(self) -> Dict[str, Any]:
        """Generate a comparison report for ablation study."""
        report = {
            "session_id": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "results": {},
        }

        # Collect all metrics
        for key, metrics in self._metrics.items():
            metrics.calculate_derived_metrics()
            report["results"][metrics.variant_name] = metrics.to_dict()

        report["end_time"] = datetime.now().isoformat()

        # Save report
        report_path = self.results_dir / "ablation_study_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        return report

    def _calculate_comparisons(self, fuzzers: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comparison metrics between fuzzers."""
        if not fuzzers:
            return {}

        # Find baseline (boofuzz)
        baseline_key = None
        for key, data in fuzzers.items():
            if data.get("variant_name") == "baseline":
                baseline_key = key
                break

        comparisons = {
            "crash_effectiveness": {},
            "cve_coverage": {},
            "speed_comparison": {},
            "llm_overhead": {},
        }

        baseline_crashes = fuzzers[baseline_key]["unique_crashes"] if baseline_key else 1
        baseline_cves = fuzzers[baseline_key]["total_cve_triggers"] if baseline_key else 1
        baseline_speed = fuzzers[baseline_key]["requests_per_second"] if baseline_key else 1

        for key, data in fuzzers.items():
            # Crash effectiveness (relative to baseline)
            comparisons["crash_effectiveness"][key] = {
                "unique_crashes": data.get("unique_crashes", 0),
                "relative_to_baseline": data.get("unique_crashes", 0) / max(baseline_crashes, 1),
            }

            # CVE coverage
            comparisons["cve_coverage"][key] = {
                "cves_found": data.get("total_cve_triggers", 0),
                "relative_to_baseline": data.get("total_cve_triggers", 0) / max(baseline_cves, 1),
            }

            # Speed comparison
            comparisons["speed_comparison"][key] = {
                "requests_per_second": data.get("requests_per_second", 0),
                "relative_to_baseline": data.get("requests_per_second", 0) / max(baseline_speed, 0.001),
            }

            # LLM overhead
            if data.get("llm_requests", 0) > 0:
                comparisons["llm_overhead"][key] = {
                    "llm_requests": data.get("llm_requests", 0),
                    "llm_tokens": data.get("llm_tokens_used", 0),
                    "avg_latency_ms": data.get("llm_avg_latency_ms", 0),
                }

        return comparisons

    def export_csv(self, output_file: str = None) -> str:
        """Export metrics to CSV for further analysis."""
        import csv

        output_file = output_file or str(self.results_dir / "metrics.csv")

        headers = [
            "variant_name", "session_id", "duration_seconds",
            "total_iterations", "requests_per_second",
            "crashes_found", "unique_crashes", "total_cve_triggers",
            "unique_cves", "avg_response_time_ms", "llm_requests", "llm_tokens_used",
            "seeds_generated", "seeds_from_llm", "mutations_performed",
            "mutations_from_llm", "error_count", "timeout_count",
            "time_to_first_crash", "time_to_first_cve"
        ]

        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

            for metrics in self._metrics.values():
                metrics.calculate_derived_metrics()
                writer.writerow({
                    "variant_name": metrics.variant_name,
                    "session_id": metrics.session_id,
                    "duration_seconds": metrics.duration_seconds,
                    "total_iterations": metrics.total_iterations,
                    "requests_per_second": metrics.requests_per_second,
                    "crashes_found": metrics.crashes_found,
                    "unique_crashes": metrics.unique_crashes,
                    "total_cve_triggers": metrics.total_cve_triggers,
                    "unique_cves": len(metrics.cve_triggers),
                    "avg_response_time_ms": metrics.avg_response_time_ms,
                    "llm_requests": metrics.llm_requests,
                    "llm_tokens_used": metrics.llm_tokens_used,
                    "seeds_generated": metrics.seeds_generated,
                    "seeds_from_llm": metrics.seeds_from_llm,
                    "mutations_performed": metrics.mutations_performed,
                    "mutations_from_llm": metrics.mutations_from_llm,
                    "error_count": metrics.error_count,
                    "timeout_count": metrics.timeout_count,
                    "time_to_first_crash": metrics.time_to_first_crash,
                    "time_to_first_cve": metrics.time_to_first_cve,
                })

        return output_file


class RealTimeDisplay:
    """Real-time display of fuzzing progress."""

    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.console = Console()
        self._running = False
        self._thread = None

    def start(self, fuzzer_type: str, session_id: str, refresh_interval: float = 2.0):
        """Start real-time display updates."""
        self._running = True
        self._thread = threading.Thread(
            target=self._update_loop,
            args=(fuzzer_type, session_id, refresh_interval),
            daemon=True
        )
        self._thread.start()

    def stop(self):
        """Stop real-time display."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _update_loop(self, fuzzer_type: str, session_id: str, interval: float):
        """Background loop to update display."""
        while self._running:
            self._display_progress(fuzzer_type, session_id)
            time.sleep(interval)

    def _display_progress(self, fuzzer_type: str, session_id: str):
        """Display current progress."""
        metrics = self.metrics.get_metrics(fuzzer_type, session_id)
        if not metrics:
            return

        # Create a compact progress line
        cve_count = len(metrics.cve_triggers)
        elapsed = time.time() - self.metrics._session_start_times.get(f"{fuzzer_type}_{session_id}", time.time())

        line = (
            f"[cyan]{fuzzer_type}[/cyan] | "
            f"Iter: [green]{metrics.total_iterations}[/green] | "
            f"Crashes: [red]{metrics.crashes_found}[/red] | "
            f"CVEs: [yellow]{cve_count}[/yellow] | "
            f"Errors: {metrics.error_count} | "
            f"Time: {elapsed:.1f}s"
        )

        # Print without newline to update in place
        self.console.print(line, end="\r")
