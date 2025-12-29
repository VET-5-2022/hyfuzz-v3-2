#!/usr/bin/env python3
"""
结果分析脚本 - 分析漏洞测试结果
Result Analysis Script - Analyze vulnerability testing results
"""
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box


class ResultAnalyzer:
    """分析漏洞测试结果的类"""

    def __init__(self, result_file: str):
        self.result_file = Path(result_file)
        self.console = Console()
        self.data = None

    def load_data(self):
        """加载测试结果数据"""
        if not self.result_file.exists():
            self.console.print(f"[red]错误: 文件不存在 {self.result_file}[/red]")
            return False

        with open(self.result_file, 'r') as f:
            self.data = json.load(f)

        return True

    def display_summary(self):
        """显示测试摘要"""
        if not self.data:
            return

        self.console.print()
        self.console.print(Panel.fit(
            "[bold blue]漏洞测试结果分析[/bold blue]",
            border_style="blue"
        ))
        self.console.print()

        # 检查是否是综合报告
        if "results" in self.data and "summary" in self.data:
            self._display_combined_summary()
        else:
            self._display_single_target_summary()

    def _display_combined_summary(self):
        """显示综合报告摘要"""
        summary = self.data.get("summary", {})

        # 创建摘要表
        table = Table(
            title="测试总览",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )

        table.add_column("指标", style="cyan", width=25)
        table.add_column("数值", justify="right", style="green", width=15)

        table.add_row("测试时间", self.data.get("test_date", "N/A"))
        table.add_row("测试框架", self.data.get("framework", "N/A"))
        table.add_row("测试目标", ", ".join(self.data.get("targets_tested", [])))
        table.add_row("总迭代次数", str(summary.get("total_iterations", 0)))
        table.add_row("发现的唯一CVE", str(summary.get("total_unique_cves", 0)))
        table.add_row("CVE触发总次数", str(summary.get("total_cve_triggers", 0)))
        table.add_row("崩溃总次数", str(summary.get("total_crashes", 0)))

        self.console.print(table)
        self.console.print()

        # 显示每个目标的详细信息
        for target_name, target_data in self.data.get("results", {}).items():
            self._display_target_details(target_name, target_data)

    def _display_single_target_summary(self):
        """显示单个目标的摘要"""
        target_name = self.data.get("target_name", "Unknown")
        self._display_target_details(target_name, self.data)

    def _display_target_details(self, target_name: str, data: Dict[str, Any]):
        """显示目标详细信息"""
        # 基本信息
        table = Table(
            title=f"{target_name} 详细信息",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan"
        )

        table.add_column("类别", style="yellow", width=25)
        table.add_column("指标", style="cyan", width=30)
        table.add_column("数值", justify="right", style="green", width=15)

        # 测试执行
        test_exec = data.get("test_execution", {})
        table.add_row(
            "测试执行",
            "总迭代次数",
            str(test_exec.get("total_iterations", 0))
        )
        table.add_row(
            "",
            "成功测试",
            str(test_exec.get("successful_tests", 0))
        )
        table.add_row(
            "",
            "失败测试",
            str(test_exec.get("failed_tests", 0))
        )

        # 漏洞发现
        vuln_disc = data.get("vulnerability_discovery", {})
        table.add_row(
            "漏洞发现",
            "发现的唯一CVE",
            str(vuln_disc.get("unique_cves_found", 0))
        )
        table.add_row(
            "",
            "CVE触发总次数",
            str(vuln_disc.get("total_cve_triggers", 0))
        )

        # 崩溃分析
        crash = data.get("crash_analysis", {})
        table.add_row(
            "崩溃分析",
            "崩溃总次数",
            str(crash.get("total_crashes", 0))
        )
        table.add_row(
            "",
            "唯一崩溃",
            str(crash.get("unique_crashes", 0))
        )

        # 时间指标
        timing = data.get("timing_metrics", {})
        ttfc = timing.get("time_to_first_crash")
        ttfcve = timing.get("time_to_first_cve")

        table.add_row(
            "时间指标",
            "首次崩溃时间 (TTFC)",
            f"{ttfc:.2f}s" if ttfc else "N/A"
        )
        table.add_row(
            "",
            "首次CVE触发时间",
            f"{ttfcve:.2f}s" if ttfcve else "N/A"
        )

        # 性能
        perf = data.get("performance", {})
        table.add_row(
            "性能指标",
            "请求速率 (req/s)",
            f"{perf.get('requests_per_second', 0):.2f}"
        )
        table.add_row(
            "",
            "平均响应时间 (ms)",
            f"{perf.get('avg_response_time_ms', 0):.2f}"
        )

        self.console.print(table)
        self.console.print()

        # CVE详细分解
        if vuln_disc.get("unique_cves_found", 0) > 0:
            self._display_cve_breakdown(target_name, vuln_disc)

    def _display_cve_breakdown(self, target_name: str, vuln_data: Dict[str, Any]):
        """显示CVE详细分解"""
        table = Table(
            title=f"{target_name} CVE分解",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold yellow"
        )

        table.add_column("CVE ID", style="yellow", width=20)
        table.add_column("严重程度", style="red", width=18)
        table.add_column("触发次数", justify="right", style="green", width=12)
        table.add_column("首次触发 (s)", justify="right", style="blue", width=15)

        cve_breakdown = vuln_data.get("cve_breakdown", {})
        cve_severity = vuln_data.get("cve_severity", {})
        cve_first_trigger = vuln_data.get("cve_first_trigger_time", {})

        # 按触发次数排序
        sorted_cves = sorted(
            cve_breakdown.items(),
            key=lambda x: x[1],
            reverse=True
        )

        for cve_id, count in sorted_cves:
            severity = cve_severity.get(cve_id, "UNKNOWN")
            first_trigger = cve_first_trigger.get(cve_id, 0)

            table.add_row(
                cve_id,
                severity,
                str(count),
                f"{first_trigger:.2f}"
            )

        self.console.print(table)
        self.console.print()

    def generate_statistics(self):
        """生成统计信息"""
        if not self.data:
            return

        self.console.print(Panel.fit(
            "[bold green]统计分析[/bold green]",
            border_style="green"
        ))
        self.console.print()

        if "results" in self.data:
            # 综合报告统计
            all_cves = set()
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

            for target_data in self.data["results"].values():
                vuln_data = target_data.get("vulnerability_discovery", {})
                cve_severity = vuln_data.get("cve_severity", {})

                all_cves.update(vuln_data.get("cve_breakdown", {}).keys())

                for severity in cve_severity.values():
                    severity_level = severity.split()[0]  # "CRITICAL (9.8)" -> "CRITICAL"
                    if severity_level in severity_counts:
                        severity_counts[severity_level] += 1

            # 显示CVE严重程度分布
            table = Table(
                title="CVE严重程度分布",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold magenta"
            )

            table.add_column("严重程度", style="yellow", width=15)
            table.add_column("CVE数量", justify="right", style="red", width=12)
            table.add_column("百分比", justify="right", style="blue", width=12)

            total = sum(severity_counts.values())
            for severity, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    percentage = (count / total * 100) if total > 0 else 0
                    table.add_row(
                        severity,
                        str(count),
                        f"{percentage:.1f}%"
                    )

            self.console.print(table)
            self.console.print()

        self.console.print("[green]分析完成！[/green]")
        self.console.print()


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="分析漏洞测试结果",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 分析综合报告
  python analyze_results.py results/vulnerability_testing/combined_vuln_test_*.json

  # 分析FTP结果
  python analyze_results.py results/vulnerability_testing/ftp_vuln_test_*.json

  # 分析HTTP结果
  python analyze_results.py results/vulnerability_testing/http_vuln_test_*.json
        """
    )

    parser.add_argument(
        "result_file",
        help="测试结果JSON文件路径"
    )

    args = parser.parse_args()

    # 创建分析器并运行
    analyzer = ResultAnalyzer(args.result_file)

    if analyzer.load_data():
        analyzer.display_summary()
        analyzer.generate_statistics()


if __name__ == "__main__":
    main()
