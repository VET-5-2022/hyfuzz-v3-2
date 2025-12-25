"""
Ollama client for LLM-based fuzzing operations.
Supports both seed generation and mutation using local LLM models.
"""
import time
import json
import logging
import re
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass

try:
    import ollama
except ImportError:
    ollama = None


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    tokens_used: int
    latency_ms: float
    model: str
    success: bool
    error: str = ""


class OllamaClient:
    """
    Client for interacting with Ollama LLM models.
    Provides seed generation and mutation capabilities.
    """

    # Prompt templates for different operations
    SEED_GENERATION_PROMPT = """You are an expert in FTP protocol security testing and fuzzing.
Generate {count} unique FTP command sequences that could potentially trigger vulnerabilities.

Target CVEs to test:
- CVE-2024-46483: Xlight FTP heap overflow (long strings >1024 chars, \\xff patterns)
- CVE-2024-4040: CrushFTP SSTI (${{, {{, <INCLUDE>, sessions.obj, users.xml)
- CVE-2024-48651: ProFTPD SQL injection (admin'--, ' OR '1'='1, UNION SELECT)
- CVE-2023-51713: ProFTPD OOB read (trailing backslash \\, unbalanced quotes)
- CVE-2022-34977: PureFTPd MLSD overflow (long MLSD args >500 chars)
- CVE-2019-12815: mod_copy (SITE CPFR/CPTO with path traversal)

Attack techniques:
1. Heap overflow: strings >1024 chars, \\xff\\xff\\xff patterns
2. Template injection: ${{env}}, {{{{config}}}}, sessions.obj
3. SQL injection: admin'--, ' OR '1'='1, ' UNION SELECT
4. Quote/backslash bugs: trailing \\, '\\, unbalanced quotes
5. Path traversal: ../../../etc/passwd
6. Format strings: %n%n%n, %s%s%s
7. NULL byte: \\x00 injection

Known vulnerable FTP commands: USER, PASS, CWD, MKD, RMD, DELE, RETR, STOR, SITE, PORT, MLSD

Output ONLY the FTP commands, one per line, in the format: COMMAND arguments
Do not include explanations or comments.

Example output:
USER admin'--
CWD ../../../etc/passwd
SITE CPFR ${{/etc/passwd}}
MLSD AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
RETR sessions.obj
PASS ' OR '1'='1
MKD test\\
"""

    MUTATION_PROMPT = """You are an expert in FTP protocol fuzzing and mutation strategies.

Given the following FTP command seed:
{seed}

Apply intelligent mutations targeting these 2024 CVEs:
- CVE-2024-46483: Add long strings (>1024 chars) or \\xff bytes for heap overflow
- CVE-2024-4040: Add template injection (${{, {{{{}}}}, sessions.obj)
- CVE-2024-48651: Add SQL injection (admin'--, ' OR '1'='1)
- CVE-2023-51713: Add trailing backslash or unbalanced quotes

Mutation strategies:
1. Extend string to 1500+ chars for heap overflow
2. Append template patterns: ${{env}}, {{{{7*7}}}}
3. Append SQL injection: ' OR '1'='1, admin'--
4. Add trailing backslash: \\, or quote patterns: '\\
5. Add path traversal: ../../../
6. Add format strings: %n%n%n

Output ONLY the mutated command, nothing else.
"""

    FEEDBACK_PROMPT = """You are an expert fuzzing strategist analyzing FTP server responses.

Current fuzzing statistics:
- Iterations completed: {iterations}
- Crashes found: {crashes}
- CVEs triggered: {cves}
- Most effective command types: {effective_commands}
- Recent responses: {recent_responses}

Based on this feedback, suggest:
1. Which command types should be prioritized (percentage weights)
2. What mutation strategies are most promising
3. Specific seed patterns to try

Output your response in JSON format:
{{
    "command_weights": {{"USER": 0.2, "CWD": 0.3, ...}},
    "mutation_priorities": ["buffer_overflow", "path_traversal", ...],
    "suggested_seeds": ["COMMAND args", ...]
}}
"""

    def __init__(
        self,
        host: str = "http://localhost:11434",
        seed_model: str = "qwen3:8b",
        mutation_model: str = "qwen3:8b",
        timeout: int = 60,  # Reduced timeout for faster fallback
        temperature: float = 0.7,
    ):
        self.host = host
        self.seed_model = seed_model
        self.mutation_model = mutation_model
        self.timeout = timeout
        self.temperature = temperature

        # Check if ollama is available
        if ollama is None:
            logging.warning("Ollama package not installed. LLM features will be disabled.")

        self._available = self._check_availability()
        self._call_count = 0  # Track number of LLM calls

    def _check_availability(self) -> bool:
        """Check if Ollama server is available."""
        if ollama is None:
            return False

        try:
            # Try to list models
            ollama.list()
            return True
        except Exception as e:
            logging.warning(f"Ollama server not available: {e}")
            return False

    @property
    def is_available(self) -> bool:
        """Check if LLM client is available."""
        return self._available

    def warmup(self, models: List[str] = None) -> Dict[str, bool]:
        """
        Warm up LLM models by sending a simple prompt to load them into memory.
        This significantly reduces latency for subsequent calls.

        Args:
            models: List of models to warm up. If None, warms up both seed and mutation models.

        Returns:
            Dict mapping model names to success status.
        """
        if not self._available:
            logging.warning("Ollama not available, skipping warmup")
            return {}

        if models is None:
            models = [self.seed_model, self.mutation_model]
            # Remove duplicates while preserving order
            models = list(dict.fromkeys(models))

        results = {}
        warmup_prompt = "Say 'ready' in one word."

        for model in models:
            logging.info(f"Warming up LLM model: {model}...")
            start_time = time.time()

            try:
                response = ollama.generate(
                    model=model,
                    prompt=warmup_prompt,
                    options={
                        "temperature": 0.1,
                        "num_predict": 10,  # Very short response
                    }
                )
                latency = time.time() - start_time
                logging.info(f"Model {model} warmed up in {latency:.1f}s")
                results[model] = True

            except Exception as e:
                latency = time.time() - start_time
                logging.warning(f"Failed to warm up {model} after {latency:.1f}s: {e}")
                results[model] = False

        return results

    def _call_model(
        self,
        model: str,
        prompt: str,
        max_tokens: int = 1024,  # Reduced for faster responses
    ) -> LLMResponse:
        """Make a call to the specified model."""
        if not self._available:
            return LLMResponse(
                content="",
                tokens_used=0,
                latency_ms=0,
                model=model,
                success=False,
                error="Ollama not available"
            )

        start_time = time.time()
        self._call_count += 1

        try:
            logging.info(f"LLM call #{self._call_count} to {model}...")

            response = ollama.generate(
                model=model,
                prompt=prompt,
                options={
                    "temperature": self.temperature,
                    "num_predict": max_tokens,
                }
            )

            latency_ms = (time.time() - start_time) * 1000
            logging.info(f"LLM call #{self._call_count} completed in {latency_ms/1000:.1f}s")

            return LLMResponse(
                content=response.get("response", ""),
                tokens_used=response.get("eval_count", 0),
                latency_ms=latency_ms,
                model=model,
                success=True,
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            logging.error(f"LLM call #{self._call_count} failed after {latency_ms/1000:.1f}s: {e}")
            return LLMResponse(
                content="",
                tokens_used=0,
                latency_ms=latency_ms,
                model=model,
                success=False,
                error=str(e)
            )

    def generate_seeds(self, count: int = 10) -> Tuple[List[str], LLMResponse]:
        """
        Generate FTP command seeds using the LLM.

        Args:
            count: Number of seeds to generate

        Returns:
            Tuple of (list of seed commands, LLM response metadata)
        """
        prompt = self.SEED_GENERATION_PROMPT.format(count=count)
        response = self._call_model(self.seed_model, prompt)

        if not response.success:
            return [], response

        # Parse the response to extract commands
        seeds = self._parse_commands(response.content)

        return seeds, response

    def mutate_seed(self, seed: str) -> Tuple[str, LLMResponse]:
        """
        Mutate a seed using the LLM.

        Args:
            seed: The seed command to mutate

        Returns:
            Tuple of (mutated command, LLM response metadata)
        """
        prompt = self.MUTATION_PROMPT.format(seed=seed)
        response = self._call_model(self.mutation_model, prompt)

        if not response.success:
            return seed, response

        # Extract the mutated command
        mutated = self._extract_single_command(response.content)

        return mutated if mutated else seed, response

    def get_feedback_strategy(
        self,
        iterations: int,
        crashes: int,
        cves: List[str],
        effective_commands: Dict[str, int],
        recent_responses: List[str],
    ) -> Tuple[Dict[str, Any], LLMResponse]:
        """
        Get fuzzing strategy based on feedback.

        Args:
            iterations: Number of iterations completed
            crashes: Number of crashes found
            cves: List of CVEs triggered
            effective_commands: Command types that caused crashes
            recent_responses: Recent server responses

        Returns:
            Tuple of (strategy dict, LLM response metadata)
        """
        prompt = self.FEEDBACK_PROMPT.format(
            iterations=iterations,
            crashes=crashes,
            cves=", ".join(cves) if cves else "None",
            effective_commands=json.dumps(effective_commands),
            recent_responses="\n".join(recent_responses[-10:]),
        )

        response = self._call_model(self.mutation_model, prompt)

        if not response.success:
            return self._default_strategy(), response

        # Parse the JSON response
        strategy = self._parse_strategy(response.content)

        return strategy, response

    def _parse_commands(self, content: str) -> List[str]:
        """Parse LLM output to extract FTP commands."""
        commands = []

        # Remove thinking blocks (deepseek-r1 format)
        import re
        content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)
        content = re.sub(r'<thought>.*?</thought>', '', content, flags=re.DOTALL)

        # Known FTP commands
        ftp_commands = [
            "USER", "PASS", "CWD", "MKD", "RMD", "DELE", "RETR", "STOR",
            "SITE", "PORT", "PASV", "LIST", "NLST", "PWD", "QUIT", "TYPE",
            "RNFR", "RNTO", "ABOR", "FEAT", "OPTS", "AUTH", "MLSD", "MLST",
        ]

        # Split by newlines and filter
        lines = content.strip().split("\n")

        for line in lines:
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # Remove common prefixes (bullet points, numbers, etc.)
            line = re.sub(r'^[\d]+[\.\)]\s*', '', line)  # "1. " or "1) "
            line = re.sub(r'^[-*•]\s*', '', line)  # "- " or "* " or "• "
            line = re.sub(r'^`+', '', line)  # backticks
            line = re.sub(r'`+$', '', line)  # trailing backticks
            line = line.strip()

            # Skip lines that look like explanations (but not too aggressively)
            if len(line) > 300:
                continue

            # Skip lines with certain patterns that indicate explanations
            if line.startswith("Here") or line.startswith("This") or line.startswith("The"):
                continue

            # Extract command if it contains a known FTP command
            line_upper = line.upper()
            for cmd in ftp_commands:
                if line_upper.startswith(cmd + " ") or line_upper == cmd:
                    commands.append(line)
                    break
                # Also check if the command is in the middle (after removing prefixes)
                elif f" {cmd} " in f" {line_upper} ":
                    # Find and extract just the FTP command part
                    idx = line_upper.find(cmd)
                    if idx >= 0:
                        extracted = line[idx:].strip()
                        if extracted:
                            commands.append(extracted)
                            break

        # Log what we found for debugging
        if commands:
            logging.debug(f"Parsed {len(commands)} FTP commands from LLM response")
        else:
            logging.warning(f"No FTP commands found in LLM response. Content preview: {content[:200]}...")

        return commands

    def _extract_single_command(self, content: str) -> Optional[str]:
        """Extract a single command from LLM output."""
        commands = self._parse_commands(content)
        return commands[0] if commands else None

    def _parse_strategy(self, content: str) -> Dict[str, Any]:
        """Parse the strategy JSON from LLM output."""
        try:
            # Try to find JSON in the response
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

        return self._default_strategy()

    def _default_strategy(self) -> Dict[str, Any]:
        """Return default fuzzing strategy targeting 2024 CVEs."""
        return {
            "command_weights": {
                "USER": 0.12,  # CVE-2024-48651 SQL injection
                "PASS": 0.12,  # CVE-2024-48651 SQL injection
                "CWD": 0.12,   # CVE-2023-51713 quote/backslash
                "STOR": 0.10,
                "RETR": 0.12,  # CVE-2024-4040 template injection
                "SITE": 0.15,  # CVE-2019-12815 mod_copy
                "MKD": 0.08,   # CVE-2023-51713 quote/backslash
                "MLSD": 0.12,  # CVE-2022-34977 buffer overflow
                "DELE": 0.07,
            },
            "mutation_priorities": [
                "heap_overflow",      # CVE-2024-46483
                "template_injection", # CVE-2024-4040
                "sql_injection",      # CVE-2024-48651
                "quote_backslash",    # CVE-2023-51713
                "path_traversal",     # CVE-2017-7692
                "buffer_overflow",    # CVE-2022-34977
                "format_string",
            ],
            "suggested_seeds": [
                "USER admin'--",
                "MLSD " + "A" * 600,
                "RETR ${config}",
                "CWD /tmp\\",
            ],
        }

    def batch_generate_seeds(
        self,
        count: int,
        batch_size: int = 10,
    ) -> Tuple[List[str], List[LLMResponse]]:
        """
        Generate seeds in batches.

        Args:
            count: Total number of seeds to generate
            batch_size: Number of seeds per batch

        Returns:
            Tuple of (all seeds, all responses)
        """
        all_seeds = []
        all_responses = []

        remaining = count
        while remaining > 0:
            batch_count = min(batch_size, remaining)
            seeds, response = self.generate_seeds(batch_count)
            all_seeds.extend(seeds)
            all_responses.append(response)
            remaining -= len(seeds)

            # Small delay between batches
            if remaining > 0:
                time.sleep(0.5)

        return all_seeds, all_responses

    def batch_mutate(
        self,
        seeds: List[str],
    ) -> Tuple[List[str], List[LLMResponse]]:
        """
        Mutate multiple seeds.

        Args:
            seeds: List of seeds to mutate

        Returns:
            Tuple of (mutated seeds, responses)
        """
        mutated = []
        responses = []

        for seed in seeds:
            mutated_seed, response = self.mutate_seed(seed)
            mutated.append(mutated_seed)
            responses.append(response)

            # Small delay between mutations
            time.sleep(0.2)

        return mutated, responses
