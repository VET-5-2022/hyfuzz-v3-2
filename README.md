# HyFuzz v3-2: LLM-Enhanced Protocol Fuzzing Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A comprehensive protocol fuzzing framework with Large Language Model (LLM) integration for security research and ablation studies. HyFuzz v3-2 systematically evaluates the effectiveness of LLMs in automated vulnerability discovery across FTP and HTTP protocols.

## Overview

HyFuzz v3-2 is a research-oriented fuzzing framework designed to answer critical questions about LLM-assisted security testing:

- **Can LLMs generate more effective fuzzing payloads than traditional methods?**
- **Do LLM-based mutations discover vulnerabilities faster?**
- **How does feedback-driven LLM guidance compare to static strategies?**
- **What is the performance cost of LLM integration?**

### Key Features

- **Dual Protocol Support**: Comprehensive FTP and HTTP protocol fuzzing
- **20 Simulated CVEs**: Real-world vulnerability patterns for evaluation
- **5 Fuzzer Variants**: Systematic ablation study design
- **LLM Integration**: Seamless Ollama integration with local models
- **Auto-Recovery**: Automatic target server restart after crashes
- **Rich Metrics**: Detailed performance and coverage analytics
- **Production-Ready**: Clean architecture, comprehensive logging, and test coverage

## Table of Contents

- [Architecture](#architecture)
- [Protocol Support](#protocol-support)
- [Fuzzer Variants](#fuzzer-variants)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Ablation Study](#ablation-study)
- [Results Interpretation](#results-interpretation)
- [Development](#development)
- [Research Applications](#research-applications)
- [License](#license)
- [Disclaimer](#disclaimer)

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        HyFuzz v3-2                              │
│                                                                 │
│  ┌──────────────┐              ┌──────────────┐                │
│  │  FTP Module  │              │ HTTP Module  │                │
│  │              │              │              │                │
│  │  10 CVEs     │              │  10 CVEs     │                │
│  │  5 Fuzzers   │              │  5 Fuzzers   │                │
│  └──────┬───────┘              └──────┬───────┘                │
│         │                             │                        │
│         └─────────────┬───────────────┘                        │
│                       │                                        │
│              ┌────────▼────────┐                               │
│              │  LLM Engine     │                               │
│              │  (Ollama)       │                               │
│              │                 │                               │
│              │  • qwen3:8b     │                               │
│              │  • Seed Gen     │                               │
│              │  • Mutation     │                               │
│              │  • Feedback     │                               │
│              └─────────────────┘                               │
└─────────────────────────────────────────────────────────────────┘
```

## Protocol Support

### FTP Protocol Fuzzing

The FTP module includes a custom vulnerable server with 10 simulated CVE vulnerabilities:

| CVE ID | Severity | CVSS | Description |
|--------|----------|------|-------------|
| CVE-2024-46483 | CRITICAL | 9.8 | Xlight FTP Heap Overflow (pre-auth integer overflow) |
| CVE-2024-4040 | CRITICAL | 9.8 | CrushFTP SSTI/RCE (server-side template injection) |
| CVE-2024-48651 | HIGH | 7.5 | ProFTPD mod_sql Privilege Escalation (GID 0) |
| CVE-2023-51713 | HIGH | 7.5 | ProFTPD OOB Read DoS (quote/backslash mishandling) |
| CVE-2022-34977 | CRITICAL | 9.8 | PureFTPd Buffer Overflow (MLSD command) |
| CVE-2019-12815 | CRITICAL | 9.8 | ProFTPD mod_copy (arbitrary file copy) |
| CVE-2019-18217 | HIGH | 7.5 | ProFTPD CWD Crash (invalid memory access) |
| CVE-2015-3306 | HIGH | 7.5 | ProFTPD mod_copy File Read |
| CVE-2010-4221 | CRITICAL | 10.0 | ProFTPD IAC Overflow (Telnet IAC buffer overflow) |
| CVE-2017-7692 | HIGH | 8.1 | FTP Path Traversal (directory commands) |

**Total**: 6 Critical, 4 High

### HTTP Protocol Fuzzing

The HTTP module includes a Flask-based vulnerable server with 10 HTTP-related CVEs:

| CVE ID | Description | Attack Vector |
|--------|-------------|---------------|
| CVE-2021-44228 | Log4Shell | JNDI injection via headers |
| CVE-2023-44487 | HTTP/2 Rapid Reset | Resource exhaustion |
| CVE-2023-25690 | Apache mod_proxy | Request splitting |
| CVE-2022-22720 | Apache HTTP Server | Request smuggling |
| CVE-2021-40438 | Apache mod_proxy | SSRF vulnerability |
| CVE-2021-41773 | Apache Path Traversal | Path manipulation |
| CVE-2023-27522 | Apache mod_proxy_uwsgi | Response smuggling |
| CVE-2022-31813 | Apache X-Forwarded | Header bypass |
| CVE-2022-26377 | Apache mod_proxy_ajp | AJP smuggling |
| CVE-2021-33193 | Apache HTTP/2 | Method confusion |

## Fuzzer Variants

HyFuzz v3-2 implements five distinct fuzzer variants for systematic ablation study:

| Variant | Seed Generation | Mutation | Description |
|---------|----------------|----------|-------------|
| **1. Baseline** | Boofuzz | Boofuzz | Pure traditional fuzzing (control group) |
| **2. LLM Seed** | qwen3:8b | Boofuzz | LLM generates initial payloads |
| **3. LLM Mutation** | Boofuzz | qwen3:8b | LLM performs payload mutations |
| **4. LLM Full** | qwen3:8b | qwen3:8b | Full LLM integration |
| **5. Feedback** | Boofuzz (weighted) | Boofuzz (weighted) | LLM analyzes feedback and adjusts strategy |

### Design Rationale

1. **Baseline**: Establishes performance benchmark
2. **LLM Seed**: Tests protocol-aware payload generation
3. **LLM Mutation**: Tests creative mutation capabilities
4. **LLM Full**: Tests combined LLM effectiveness
5. **Feedback**: Tests adaptive strategy adjustment

## Installation

### Prerequisites

- **Python**: 3.8 or higher
- **Ollama**: Local LLM runtime
- **Operating System**: Linux, macOS, or WSL2
- **Memory**: 8GB+ RAM recommended
- **Disk Space**: 10GB+ for models and logs

### System Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv git

# macOS
brew install python3 git
```

### Ollama Setup

```bash
# Install Ollama
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama service
ollama serve

# Pull required model (in a new terminal)
ollama pull qwen3:8b
```

### HyFuzz Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/hyfuzz-v3-2.git
cd hyfuzz-v3-2

# Install FTP module dependencies
cd FTP
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cd ..

# Install HTTP module dependencies
cd HTTP
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd ..
```

## Quick Start

### FTP Fuzzing

```bash
cd FTP
source venv/bin/activate

# Run baseline fuzzer
python main.py --fuzzer baseline --iterations 1000

# Run full ablation study
python main.py --ablation --iterations 500

# Run server only (for manual testing)
python main.py --server-only
```

### HTTP Fuzzing

```bash
cd HTTP
source venv/bin/activate

# Run all fuzzer variants
python run_ablation.py

# Run specific variants
python run_ablation.py --variants boofuzz_baseline llm_seed

# Custom iterations
python run_ablation.py --iterations 500
```

## Usage

### FTP Module Commands

```bash
# Basic usage
python main.py --fuzzer <variant> --iterations <count>

# Available fuzzer variants:
# - baseline       : Pure boofuzz fuzzing
# - llm_seed       : LLM seed generation
# - llm_mutation   : LLM mutation
# - llm_full       : Full LLM integration
# - feedback       : Feedback-driven fuzzing

# Example: Run LLM-full fuzzer with 2000 iterations
python main.py --fuzzer llm_full --iterations 2000 --verbose

# Run complete ablation study (all variants)
python main.py --ablation --iterations 1000

# Advanced options
python main.py \
  --fuzzer feedback \
  --iterations 5000 \
  --host 127.0.0.1 \
  --port 2121 \
  --ollama-host http://localhost:11434 \
  --seed-model qwen3:8b \
  --mutation-model qwen3:8b \
  --results-dir ./my_results \
  --verbose
```

### HTTP Module Commands

```bash
# Run ablation study with all variants
python run_ablation.py

# Run specific variants
python run_ablation.py --variants boofuzz_baseline llm_full

# Custom configuration
python run_ablation.py --config custom_config.yaml

# Run target server only
python run_ablation.py --target-only

# Specify iterations
python run_ablation.py --iterations 2000
```

### Command-Line Options

#### FTP Module

| Option | Description | Default |
|--------|-------------|---------|
| `--fuzzer`, `-f` | Fuzzer variant to run | baseline |
| `--iterations`, `-i` | Number of iterations | 1000 |
| `--ablation`, `-a` | Run ablation study | False |
| `--server-only`, `-s` | Run server only | False |
| `--host` | FTP server host | 127.0.0.1 |
| `--port`, `-p` | FTP server port | 2121 |
| `--ollama-host` | Ollama server URL | http://localhost:11434 |
| `--seed-model` | LLM for seed generation | qwen3:8b |
| `--mutation-model` | LLM for mutations | qwen3:8b |
| `--results-dir` | Results directory | ./results |
| `--verbose`, `-v` | Verbose logging | False |

#### HTTP Module

| Option | Description | Default |
|--------|-------------|---------|
| `--variants` | Fuzzer variants to run | all |
| `--iterations` | Iterations per variant | 1000 |
| `--config` | Configuration file | config/config.yaml |
| `--target-only` | Run target server only | False |

## Project Structure

```
hyfuzz-v3-2/
├── FTP/                          # FTP Protocol Fuzzing Module
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py           # Configuration management
│   ├── target/
│   │   ├── __init__.py
│   │   ├── vulnerable_ftp_server.py  # FTP server with CVEs
│   │   ├── cve_handlers.py       # CVE implementations
│   │   ├── crash_logger.py       # Crash recording
│   │   └── server_manager.py     # Auto-restart supervisor
│   ├── fuzzer/
│   │   ├── __init__.py
│   │   ├── base_fuzzer.py        # Base fuzzer class
│   │   ├── baseline_boofuzz.py   # Variant 1: Pure boofuzz
│   │   ├── llm_seed_fuzzer.py    # Variant 2: LLM seeds
│   │   ├── llm_mutation_fuzzer.py # Variant 3: LLM mutations
│   │   ├── llm_full_fuzzer.py    # Variant 4: Full LLM
│   │   ├── feedback_fuzzer.py    # Variant 5: Feedback-driven
│   │   ├── stateful_fuzzer.py    # Stateful fuzzing support
│   │   ├── state_machine.py      # State machine implementation
│   │   └── llm_client.py         # Ollama integration
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── logger.py             # Logging utilities
│   │   └── metrics.py            # Metrics collection
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_fuzzer.py
│   │   └── test_cve_handlers.py
│   ├── results/                  # Generated results
│   ├── main.py                   # Entry point
│   ├── requirements.txt          # Dependencies
│   └── README.md                 # FTP-specific documentation
│
├── HTTP/                         # HTTP Protocol Fuzzing Module
│   ├── target/
│   │   ├── __init__.py
│   │   ├── http_server.py        # Vulnerable HTTP server
│   │   ├── cve_handlers.py       # CVE implementations
│   │   ├── crash_logger.py       # Crash logging
│   │   └── supervisor.py         # Server supervision
│   ├── fuzzer/
│   │   ├── __init__.py
│   │   ├── base_fuzzer.py        # Abstract base fuzzer
│   │   ├── boofuzz_baseline.py   # Baseline fuzzer
│   │   ├── llm_seed_fuzzer.py    # LLM seed generation
│   │   ├── llm_mutation_fuzzer.py # LLM mutation
│   │   ├── llm_full_fuzzer.py    # Full LLM fuzzer
│   │   ├── llm_feedback_fuzzer.py # Feedback-driven fuzzer
│   │   └── llm_client.py         # Ollama client
│   ├── utils/
│   │   ├── __init__.py
│   │   └── helpers.py            # Utility functions
│   ├── logs/                     # Crash and CVE logs
│   ├── results/                  # Ablation study results
│   ├── run_ablation.py           # Main entry point
│   ├── demo_realtime_progress.py # Progress monitoring demo
│   ├── test_fuzzer_logging.py   # Logging tests
│   ├── requirements.txt          # Dependencies
│   ├── README.md                 # HTTP-specific documentation
│   ├── FUZZER_LOGGING_GUIDE.md  # Logging guide
│   └── REALTIME_PROGRESS_GUIDE.md # Progress tracking guide
│
├── LICENSE                       # MIT License
└── README.md                     # This file
```

## Ablation Study

### Experimental Design

The ablation study follows rigorous scientific methodology:

1. **Control Group**: Baseline boofuzz establishes benchmark performance
2. **Isolated Variables**: Each variant modifies exactly one component
3. **Consistent Environment**: Same targets, metrics, and iteration counts
4. **Reproducibility**: Logged seeds, configurations, and random states

### Research Questions

| RQ | Question | Variants Compared |
|----|----------|-------------------|
| RQ1 | Does LLM seed generation improve crash discovery? | Baseline vs LLM Seed |
| RQ2 | Does LLM mutation enhance vulnerability coverage? | Baseline vs LLM Mutation |
| RQ3 | Is full LLM integration better than partial? | LLM Seed/Mutation vs LLM Full |
| RQ4 | Can feedback-driven LLM guidance improve efficiency? | All variants vs Feedback |
| RQ5 | What is the performance overhead of LLM integration? | All variants (runtime comparison) |

### Metrics Collected

#### Performance Metrics
- **Iterations per second (RPS)**: Fuzzing throughput
- **Total execution time**: Wall-clock duration
- **LLM API calls**: Number and latency of LLM requests
- **Memory usage**: Peak and average RAM consumption

#### Effectiveness Metrics
- **Total crashes**: All crash events
- **Unique crashes**: Deduplicated by crash hash
- **CVEs triggered**: Distinct CVE vulnerabilities found
- **Code coverage**: Percentage of target code executed
- **Time to first crash**: Discovery speed

#### Efficiency Metrics
- **Crashes per iteration**: Discovery rate
- **CVEs per hour**: Vulnerability discovery throughput
- **Cost per crash**: LLM API cost (if applicable)

## Results Interpretation

### Output Files

#### FTP Module Results (`FTP/results/`)

```
results/
├── crashes/
│   ├── crash_<hash>_<timestamp>.json
│   └── ...
├── crashes.json                  # All crash records
├── cve_triggers.json             # CVE-specific triggers
├── metrics.csv                   # Metrics in CSV format
├── ablation_study_results.json   # Complete ablation study
└── fuzzer.log                    # Detailed execution log
```

#### HTTP Module Results (`HTTP/results/`)

```
results/
├── ablation_results_<timestamp>.json
├── ablation_report_<timestamp>.txt
└── ...

logs/
├── crashes/
│   └── crash_<id>.json
└── cve_triggers/
    ├── CVE-2021-44228/
    └── ...
```

### Sample Ablation Report

```
ABLATION STUDY RESULTS
======================================================================
HyFuzz v3-2 - FTP Protocol Fuzzing
Date: 2025-12-26 10:30:00
Duration: 3h 45m 23s
======================================================================

Variant           Crashes  Unique  CVEs  Time     RPS   Overhead
----------------------------------------------------------------------
baseline               42      38     8  45m23s  22.04      -
llm_seed               58      51    10  67m45s  14.77   +49.3%
llm_mutation           47      43     9  52m34s  19.02   +15.9%
llm_full               64      58    10  89m12s  11.21   +96.7%
feedback               71      62    10  78m56s  12.66   +74.0%
----------------------------------------------------------------------

KEY FINDINGS:
1. LLM-based fuzzers discovered 25-69% more unique crashes
2. Feedback-driven approach triggered 25% more CVEs
3. LLM overhead ranges from 15.9% to 96.7%
4. Full LLM integration provides best vulnerability coverage
5. Feedback fuzzer offers optimal efficiency/effectiveness balance

CVE COVERAGE BY VARIANT:
- baseline:       8/10 CVEs (80%)
- llm_seed:      10/10 CVEs (100%)
- llm_mutation:   9/10 CVEs (90%)
- llm_full:      10/10 CVEs (100%)
- feedback:      10/10 CVEs (100%)
======================================================================
```

### Crash Record Format

Each crash is recorded with comprehensive metadata:

```json
{
  "crash_id": "a3f5e8b2c1d4f6e9",
  "timestamp": "2025-12-26T10:15:23.456789",
  "crash_type": "cve_trigger",
  "cve_id": "CVE-2019-12815",
  "protocol": "FTP",
  "command": "SITE CPFR",
  "payload": "SITE CPFR /etc/passwd",
  "payload_hex": "53 49 54 45 20 43 50 46 52 20 2F 65 74 63 2F 70 61 73 73 77 64",
  "fuzzer_variant": "llm_full",
  "iteration": 1234,
  "response": "550 Permission denied",
  "server_state": "authenticated",
  "additional_info": {
    "llm_generated": true,
    "seed_source": "qwen3:8b",
    "mutation_count": 3
  }
}
```

## Development

### Running Tests

```bash
# FTP module tests
cd FTP
pytest tests/ -v --cov=. --cov-report=html

# HTTP module tests
cd HTTP
pytest -v
```

### Code Quality

```bash
# Format code
black FTP/ HTTP/

# Lint code
flake8 FTP/ HTTP/

# Type checking
mypy FTP/ HTTP/
```

### Adding New CVE Handlers

#### FTP Module

1. Create handler in `FTP/target/cve_handlers.py`:

```python
class CVE_YYYY_XXXXX_Handler(CVEHandler):
    def __init__(self):
        super().__init__(
            cve_id="CVE-YYYY-XXXXX",
            name="Vulnerability Name",
            severity="CRITICAL",
            cvss=9.8,
            description="Detailed description"
        )

    def check_trigger(self, command: str, args: list) -> Tuple[bool, Optional[str]]:
        # Implement detection logic
        if condition:
            return True, "Trigger details"
        return False, None
```

2. Register in `CVERegistry._initialize_handlers()`

#### HTTP Module

```python
class CVE_YYYY_XXXXX_Handler(CVEHandler):
    def __init__(self):
        super().__init__(
            "CVE-YYYY-XXXXX",
            "Vulnerability description"
        )

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict]]:
        # Implement detection logic
        pass
```

### Adding New Fuzzer Variants

1. Create new fuzzer class inheriting from `BaseFuzzer`
2. Implement required methods:
   - `generate_seeds()`: Initial payload generation
   - `mutate()`: Payload mutation logic
   - `run()`: Main fuzzing loop
3. Register in module's `__init__.py`
4. Add to main entry point

### Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

#### Coding Standards

- Follow PEP 8 style guide
- Add docstrings to all public functions
- Write unit tests for new features
- Update documentation as needed
- Maintain backward compatibility

## Research Applications

### Academic Use Cases

- **Protocol Fuzzing Research**: Benchmark LLM-assisted fuzzing
- **Vulnerability Discovery**: Evaluate automated security testing
- **Machine Learning Security**: Study LLM capabilities in adversarial contexts
- **Software Testing**: Compare traditional vs AI-driven testing

### Industry Applications

- **Security Testing**: Pre-deployment vulnerability assessment
- **Penetration Testing**: Automated protocol testing
- **Training**: Security researcher education
- **Benchmarking**: Fuzzer comparison and evaluation

### Citation

If you use HyFuzz v3-2 in your research, please cite:

```bibtex
@software{hyfuzz_v3_2_2025,
  title={HyFuzz v3-2: LLM-Enhanced Protocol Fuzzing Framework},
  author={Your Name},
  year={2025},
  url={https://github.com/yourusername/hyfuzz-v3-2},
  license={MIT}
}
```

## Troubleshooting

### Common Issues

#### Ollama Connection Error

```bash
# Ensure Ollama is running
ollama serve

# Test connection
curl http://localhost:11434/api/tags
```

#### Port Already in Use

```bash
# FTP: Change port in command
python main.py --port 2122

# HTTP: Update config.yaml
target:
  port: 8081
```

#### Memory Issues

```bash
# Reduce iterations
python main.py --iterations 100

# Use lighter model
python main.py --seed-model qwen3:1b
```

#### Import Errors

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

## Performance Optimization

- **Reduce LLM Calls**: Lower `--iterations` for LLM-based fuzzers
- **Parallel Execution**: Run FTP and HTTP modules on separate machines
- **Resource Limits**: Set memory/CPU limits for target servers
- **Logging Level**: Use `--verbose` only when debugging

## Security Considerations

- **Isolated Environment**: Run in VM or container
- **Network Isolation**: Use localhost or isolated network
- **Access Control**: Restrict access to vulnerable servers
- **Data Sanitization**: Sanitize logs before sharing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 VET-5-2022

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## Disclaimer

**IMPORTANT SECURITY NOTICE**

This software is intended for:
- **Authorized security testing** in controlled environments
- **Educational purposes** and security research
- **Academic research** and vulnerability analysis
- **CTF competitions** and training scenarios

### Usage Restrictions

❌ **DO NOT USE** for:
- Unauthorized testing of systems you don't own
- Production environments without proper authorization
- Malicious purposes or illegal activities
- Systems without explicit written permission

### Legal Compliance

Users are responsible for:
- Obtaining proper authorization before testing
- Complying with applicable laws and regulations
- Following responsible disclosure practices
- Respecting privacy and security of others

### No Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. The authors and contributors are not responsible for any damages or legal issues arising from misuse of this software.

### Ethical Use

By using this software, you agree to:
- Use it only for lawful purposes
- Obtain proper authorization before testing
- Follow responsible disclosure guidelines
- Not cause harm to systems or data

## Acknowledgments

This project builds upon excellent open-source tools and research:

- **[boofuzz](https://github.com/jtpereyda/boofuzz)**: Network protocol fuzzing framework
- **[Ollama](https://github.com/ollama/ollama)**: Local LLM inference engine
- **[pyftpdlib](https://github.com/giampaolo/pyftpdlib)**: Python FTP server library
- **[Flask](https://flask.palletsprojects.com/)**: Python web framework
- **[Qwen](https://github.com/QwenLM/Qwen)**: Large language model

Special thanks to the security research community for CVE documentation and vulnerability research.

## Support

- **Documentation**: See module-specific README files
- **Issues**: [GitHub Issues](https://github.com/yourusername/hyfuzz-v3-2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/hyfuzz-v3-2/discussions)

## Roadmap

- [ ] Additional protocol support (SMTP, DNS, SMB)
- [ ] Cloud-based LLM integration (GPT-4, Claude)
- [ ] Real-time dashboard for monitoring
- [ ] Advanced mutation strategies
- [ ] Docker containerization
- [ ] Continuous integration pipeline
- [ ] Benchmark dataset publication

---

**Made with passion for security research and AI exploration**

For questions, feedback, or collaboration opportunities, please open an issue or start a discussion on GitHub.
