# HyFuzz v3 - FTP Protocol Fuzzing Framework

A comprehensive fuzzing framework for FTP protocol security testing with LLM-enhanced capabilities. This project implements an ablation study design to compare different fuzzing strategies.

## Overview

HyFuzz v3 is designed to evaluate the effectiveness of Large Language Models (LLMs) in protocol fuzzing. The framework includes:

- **Vulnerable FTP Server**: A target server with 10 simulated CVE vulnerabilities
- **Five Fuzzer Variants**: For ablation study comparison
- **Metrics Collection**: Comprehensive tracking for research analysis
- **Auto-restart**: Automatic server recovery after crashes

## Features

### Target (Vulnerable FTP Server)

The framework includes a custom FTP server with simulated vulnerabilities based on real CVEs:

| CVE ID | Name | Severity | CVSS | Description |
|--------|------|----------|------|-------------|
| CVE-2024-46483 | Xlight FTP Heap Overflow | CRITICAL | 9.8 | Pre-auth integer overflow leads to heap overflow |
| CVE-2024-4040 | CrushFTP SSTI/RCE | CRITICAL | 9.8 | Server-side template injection for RCE |
| CVE-2024-48651 | ProFTPD mod_sql Privilege Escalation | HIGH | 7.5 | GID 0 privilege escalation via SQL injection |
| CVE-2023-51713 | ProFTPD OOB Read DoS | HIGH | 7.5 | Quote/backslash mishandling causes daemon crash |
| CVE-2022-34977 | PureFTPd Buffer Overflow | CRITICAL | 9.8 | Buffer overflow in MLSD command handling |
| CVE-2019-12815 | ProFTPD mod_copy | CRITICAL | 9.8 | Arbitrary file copy via SITE CPFR/CPTO |
| CVE-2019-18217 | ProFTPD CWD Crash | HIGH | 7.5 | Invalid memory access in CWD handling |
| CVE-2015-3306 | ProFTPD mod_copy File Read | HIGH | 7.5 | Arbitrary file read vulnerability |
| CVE-2010-4221 | ProFTPD IAC Overflow | CRITICAL | 10.0 | Telnet IAC buffer overflow |
| CVE-2017-7692 | FTP Path Traversal | HIGH | 8.1 | Path traversal via directory commands |

### Fuzzer Variants (Ablation Study)

| Variant | Seed Generation | Mutation | Description |
|---------|----------------|----------|-------------|
| **Baseline** | Boofuzz | Boofuzz | Pure boofuzz (control group) |
| **LLM Seed** | qwen3:8b | Boofuzz | LLM generates seeds only |
| **LLM Mutation** | Boofuzz | qwen3:8b | LLM performs mutations only |
| **LLM Full** | qwen3:8b | qwen3:8b | LLM for both operations |
| **Feedback** | Boofuzz (weighted) | Boofuzz (weighted) | LLM adjusts strategy based on feedback |

## Installation

### Prerequisites

- Python 3.8+
- Windows with PyCharm (development environment)
- Ollama installed locally with models:
  - `qwen3:8b`
  - `qwen3:8b` (or `qwen3-vl:8b`)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/hyfuzz-v3-ftp.git
cd hyfuzz-v3-ftp
```

2. Create virtual environment:
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Ensure Ollama is running with required models:
```bash
ollama pull qwen3:8b
ollama pull qwen3:8b
ollama serve
```

## Usage

### Run Single Fuzzer

```bash
# Run baseline boofuzz fuzzer
python main.py --fuzzer baseline --iterations 1000

# Run LLM seed generation fuzzer
python main.py --fuzzer llm_seed --iterations 1000

# Run LLM mutation fuzzer
python main.py --fuzzer llm_mutation --iterations 1000

# Run full LLM fuzzer
python main.py --fuzzer llm_full --iterations 1000

# Run feedback-driven fuzzer
python main.py --fuzzer feedback --iterations 1000
```

### Run Ablation Study

```bash
# Run complete ablation study with all variants
python main.py --ablation --iterations 500
```

### Run Server Only (Manual Testing)

```bash
# Start only the vulnerable FTP server
python main.py --server-only
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--fuzzer`, `-f` | Fuzzer type to run | baseline |
| `--iterations`, `-i` | Number of iterations | 1000 |
| `--ablation`, `-a` | Run ablation study | False |
| `--server-only`, `-s` | Run server only | False |
| `--host` | FTP server host | 127.0.0.1 |
| `--port`, `-p` | FTP server port | 2121 |
| `--ollama-host` | Ollama server URL | http://localhost:11434 |
| `--seed-model` | LLM for seeds | qwen3:8b |
| `--mutation-model` | LLM for mutations | qwen3:8b |
| `--results-dir` | Results directory | ./results |
| `--verbose`, `-v` | Verbose logging | False |

## Project Structure

```
hyfuzz-v3-ftp/
├── config/
│   ├── __init__.py
│   └── settings.py          # Configuration management
├── target/
│   ├── __init__.py
│   ├── vulnerable_ftp_server.py  # FTP server with CVEs
│   ├── cve_handlers.py       # CVE vulnerability implementations
│   ├── crash_logger.py       # Crash recording
│   └── server_manager.py     # Auto-restart management
├── fuzzer/
│   ├── __init__.py
│   ├── base_fuzzer.py        # Base fuzzer class
│   ├── baseline_boofuzz.py   # Variant 1: Pure boofuzz
│   ├── llm_seed_fuzzer.py    # Variant 2: LLM seeds
│   ├── llm_mutation_fuzzer.py # Variant 3: LLM mutations
│   ├── llm_full_fuzzer.py    # Variant 4: Full LLM
│   ├── feedback_fuzzer.py    # Variant 5: Feedback-driven
│   └── llm_client.py         # Ollama client wrapper
├── utils/
│   ├── __init__.py
│   ├── logger.py             # Logging utilities
│   └── metrics.py            # Metrics collection
├── results/                  # Output directory
├── tests/                    # Unit tests
├── main.py                   # Entry point
├── requirements.txt          # Dependencies
└── README.md                 # This file
```

## Output Files

After running the fuzzer, results are stored in the `results/` directory:

- `crashes/` - Individual crash records with payloads
- `crashes.json` - All crash records
- `cve_triggers.json` - CVE-specific triggers
- `metrics.csv` - Metrics in CSV format
- `ablation_study_results.json` - Complete ablation study report
- `fuzzer.log` - Detailed execution log

## Crash Recording

Each crash is recorded with:
- Unique crash ID (hash-based)
- Timestamp
- Crash type (CVE trigger, timeout, protocol error, etc.)
- Full payload (text and hex)
- FTP command and arguments
- CVE ID (if applicable)
- Fuzzer type and iteration number

## Metrics Collected

For ablation study comparison:
- Total iterations
- Crashes found (total and unique)
- CVEs triggered
- Iterations per second
- Response times
- LLM API calls and latency
- Seeds generated (by source)
- Mutations performed (by type)

## Development

### Running Tests

```bash
pytest tests/ -v
```

### Adding New CVE Handlers

1. Create a new handler class in `target/cve_handlers.py`
2. Inherit from `CVEHandler`
3. Implement `check_trigger()` method
4. Register in `CVERegistry._initialize_handlers()`

### Adding New Fuzzer Variants

1. Create a new file in `fuzzer/`
2. Inherit from `BaseFuzzer`
3. Implement `generate_seeds()`, `mutate()`, and `run()` methods
4. Add to `fuzzer/__init__.py`
5. Register in `main.py:create_fuzzer()`

## Research Notes

### Ablation Study Design

This framework follows ablation study principles:
1. **Control Group**: Baseline boofuzz provides the benchmark
2. **Isolated Variables**: Each variant changes only one component
3. **Consistent Environment**: Same target, metrics, and iterations
4. **Reproducibility**: Seeds and configurations are logged

### Expected Outcomes

The ablation study helps answer:
- Does LLM seed generation improve crash discovery?
- Does LLM mutation improve vulnerability coverage?
- Does feedback-driven adjustment improve efficiency?
- What is the LLM overhead cost?

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- [boofuzz](https://github.com/jtpereyda/boofuzz) - Network protocol fuzzing library
- [pyftpdlib](https://github.com/giampaolo/pyftpdlib) - Python FTP server library
- [Ollama](https://github.com/ollama/ollama) - Local LLM runtime

## Disclaimer

This tool is for authorized security testing and research purposes only. Do not use against systems without explicit permission. The simulated CVEs are for testing purposes and do not represent actual exploits.
