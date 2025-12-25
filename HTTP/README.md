# HyFuzz-v3: HTTP Protocol Fuzzing with LLM Integration

A comprehensive HTTP protocol fuzzing framework designed for ablation study comparing traditional fuzzing techniques with LLM-assisted approaches.

## Overview

HyFuzz-v3 provides:

1. **Vulnerable HTTP Target Server**: A purpose-built server simulating 10 real CVE vulnerabilities
2. **Five Fuzzer Variants**: For systematic ablation study comparing different LLM integration strategies
3. **Automatic Crash Recovery**: Server supervision with automatic restart capabilities
4. **Comprehensive Logging**: Detailed crash and CVE trigger logging for analysis

## Architecture

```
hyfuzz-v3/
├── config/
│   └── config.yaml          # Configuration file
├── target/
│   ├── http_server.py       # Vulnerable HTTP server
│   ├── cve_handlers.py      # CVE vulnerability implementations
│   ├── crash_logger.py      # Crash and CVE logging
│   └── supervisor.py        # Auto-restart supervisor
├── fuzzer/
│   ├── base_fuzzer.py       # Abstract base fuzzer
│   ├── boofuzz_baseline.py  # Baseline fuzzer (boofuzz-style)
│   ├── llm_seed_fuzzer.py   # LLM seed generation
│   ├── llm_mutation_fuzzer.py # LLM mutation
│   ├── llm_full_fuzzer.py   # LLM seed + mutation
│   ├── llm_feedback_fuzzer.py # Feedback-driven LLM
│   └── llm_client.py        # Ollama integration
├── utils/
│   └── helpers.py           # Utility functions
├── logs/                    # Crash and CVE logs
├── results/                 # Ablation study results
├── run_ablation.py          # Main entry point
└── requirements.txt         # Dependencies
```

## Simulated CVE Vulnerabilities

The target server simulates these 10 HTTP-related CVEs:

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

### 1. boofuzz_baseline
Standard fuzzing using boofuzz-style seed generation and mutation. Serves as the control group.

### 2. llm_seed
- **Seed Generation**: LLM (qwen3:8b via Ollama)
- **Mutation**: Boofuzz-style

Tests whether LLM can generate more effective initial payloads.

### 3. llm_mutation
- **Seed Generation**: Boofuzz-style
- **Mutation**: LLM (qwen3:8b via Ollama)

Tests whether LLM can provide more creative mutations.

### 4. llm_full
- **Seed Generation**: LLM (qwen3:8b via Ollama)
- **Mutation**: LLM (qwen3:8b via Ollama)

Tests full LLM integration for payload generation.

### 5. llm_feedback
- **Seed Generation**: Boofuzz-style with LLM-adjusted weights
- **Mutation**: Boofuzz-style with LLM-adjusted weights
- **Strategy**: LLM analyzes feedback and adjusts strategy weights

Tests whether LLM can effectively guide fuzzing strategy based on target feedback.

## Installation

### Prerequisites

- Python 3.9+
- Ollama with qwen3:8b model installed
- macOS, Linux, or WSL

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd hyfuzz-v3

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Ollama (if not already installed)
# macOS: brew install ollama
# Linux: curl -fsSL https://ollama.com/install.sh | sh

# Pull the LLM model
ollama pull qwen3:8b
```

## Usage

### Run Full Ablation Study

```bash
# Run all variants with default settings
python run_ablation.py

# Run specific variants
python run_ablation.py --variants boofuzz_baseline llm_seed

# Custom iterations
python run_ablation.py --iterations 500

# Use custom config
python run_ablation.py --config my_config.yaml
```

### Run Target Server Only (for debugging)

```bash
python run_ablation.py --target-only
```

### Run Individual Fuzzer

```python
from fuzzer.boofuzz_baseline import BoofuzzBaseline

fuzzer = BoofuzzBaseline(
    target_host="127.0.0.1",
    target_port=8080,
    max_iterations=1000
)

result = fuzzer.run()
print(f"Crashes: {result.crashes_found}")
print(f"CVE Triggers: {result.cve_triggers}")
```

## Configuration

Edit `config/config.yaml` to customize:

```yaml
# Target Server
target:
  host: "127.0.0.1"
  port: 8080
  restart_delay: 1.0
  max_restarts: 100

# LLM Settings
llm:
  base_url: "http://localhost:11434"
  model: "qwen3:8b"
  timeout: 30
  temperature: 0.7

# Fuzzer Settings
fuzzer:
  max_iterations: 10000
  connection_timeout: 5.0
  recv_timeout: 2.0

# Ablation Study
ablation:
  iterations_per_variant: 1000
  results_dir: "results"
```

## Results

After running the ablation study, results are saved in the `results/` directory:

- `ablation_results_<timestamp>.json`: Raw results data
- `ablation_report_<timestamp>.txt`: Human-readable report

Crash and CVE trigger logs are saved in the `logs/` directory:

- `logs/crashes/`: Individual crash records
- `logs/cve_triggers/`: CVE trigger records organized by CVE ID

### Sample Output

```
ABLATION STUDY RESULTS
======================================================================
Variant              Crashes  CVE Triggers   Duration          RPS
----------------------------------------------------------------------
boofuzz_baseline          15           234     45.23s        22.11
llm_seed                  23           312     67.45s        14.83
llm_mutation              18           287     52.34s        19.10
llm_full                  28           356     89.12s        11.22
llm_feedback              31           401     78.56s        12.73
----------------------------------------------------------------------
```

## Development

### Adding New CVE Handlers

Create a new handler in `target/cve_handlers.py`:

```python
class CVE_YYYY_XXXXX_Handler(CVEHandler):
    def __init__(self):
        super().__init__(
            "CVE-YYYY-XXXXX",
            "Description of the vulnerability"
        )

    def check(self, request: Request) -> Tuple[bool, Optional[str], Optional[Dict]]:
        # Implement vulnerability detection logic
        pass
```

### Adding New Fuzzer Variants

1. Create a new fuzzer class inheriting from `BaseFuzzer`
2. Implement `generate_seed()` and `mutate()` methods
3. Register in `AblationStudy.FUZZER_VARIANTS`

## Limitations

- This is a research tool for ablation study purposes
- The target server contains intentional vulnerabilities - DO NOT use in production
- LLM-based fuzzers require a running Ollama instance
- Performance depends on hardware and LLM inference speed

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Acknowledgments

- boofuzz for fuzzing primitive inspiration
- Ollama for local LLM inference
- Flask for the target server framework
