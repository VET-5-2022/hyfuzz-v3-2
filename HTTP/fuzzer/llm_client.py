"""
Ollama LLM Client Module

Provides integration with Ollama for LLM-based seed generation and mutation.
"""

import json
import re
import time
import requests
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.helpers import setup_logging


def extract_json_from_response(response: str, logger=None) -> Optional[Dict[str, Any]]:
    """
    Extract JSON from LLM response, handling various formats including
    qwen3's thinking blocks and markdown code blocks.

    Args:
        response: Raw LLM response text
        logger: Optional logger for debug output

    Returns:
        Parsed JSON dict or None if extraction fails
    """
    if not response:
        if logger:
            logger.debug("Empty response received")
        return None

    original = response  # Keep original for debug
    cleaned = response.strip()

    # Step 1: Remove qwen3 thinking blocks <think>...</think>
    cleaned = re.sub(r'<think>.*?</think>', '', cleaned, flags=re.DOTALL)

    # Step 2: Remove any other XML-like tags (but keep content)
    cleaned = re.sub(r'<[^>]+>', '', cleaned)

    # Step 3: Remove markdown code blocks
    if '```' in cleaned:
        # Extract content between code blocks
        code_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', cleaned)
        if code_match:
            cleaned = code_match.group(1)
        else:
            # Just remove the markers
            cleaned = re.sub(r'```(?:json)?', '', cleaned)

    cleaned = cleaned.strip()

    # Step 4: Handle case where response is just text with JSON embedded
    # Remove common prefixes that qwen3 might add
    prefixes_to_remove = [
        r'^[Hh]ere\s+is\s+.*?:\s*',
        r'^[Tt]he\s+JSON\s+.*?:\s*',
        r'^[Oo]utput\s*:\s*',
        r'^[Rr]esponse\s*:\s*',
        r'^[Jj]SON\s*:\s*',
    ]
    for prefix in prefixes_to_remove:
        cleaned = re.sub(prefix, '', cleaned, flags=re.DOTALL)

    cleaned = cleaned.strip()

    # Step 5: Try to find JSON object
    # Method 1: Direct parse if it starts with {
    if cleaned.startswith('{'):
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            # Try to find just the first complete object
            pass

    # Method 2: Find first { and matching }
    start_idx = cleaned.find('{')
    if start_idx != -1:
        # Find matching closing brace
        brace_count = 0
        end_idx = -1
        in_string = False
        escape_next = False

        for i, char in enumerate(cleaned[start_idx:], start_idx):
            if escape_next:
                escape_next = False
                continue

            if char == '\\':
                escape_next = True
                continue

            if char == '"' and not escape_next:
                in_string = not in_string
                continue

            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i
                        break

        if end_idx > start_idx:
            json_str = cleaned[start_idx:end_idx + 1]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                # Try to fix common issues
                fixed = fix_json_string(json_str)
                try:
                    return json.loads(fixed)
                except json.JSONDecodeError:
                    pass

    # Method 3: Fallback - find any { ... } pattern
    end_idx = cleaned.rfind('}')
    if start_idx != -1 and end_idx > start_idx:
        json_str = cleaned[start_idx:end_idx + 1]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            fixed = fix_json_string(json_str)
            try:
                return json.loads(fixed)
            except json.JSONDecodeError:
                pass

    # Method 4: Try to construct JSON from key patterns
    # Sometimes LLM outputs partial or malformed JSON
    method_match = re.search(r'"?method"?\s*[:=]\s*"?([A-Z]+)"?', cleaned, re.IGNORECASE)
    path_match = re.search(r'"?path"?\s*[:=]\s*"([^"]*)"', cleaned, re.IGNORECASE)

    if method_match and path_match:
        # Try to reconstruct a minimal valid JSON
        method = method_match.group(1).upper()
        path = path_match.group(1)

        # Look for headers
        headers = {"Host": "localhost"}
        headers_match = re.search(r'"?headers"?\s*[:=]\s*(\{[^}]*\})', cleaned, re.IGNORECASE)
        if headers_match:
            try:
                headers = json.loads(fix_json_string(headers_match.group(1)))
            except:
                pass

        return {
            "method": method,
            "path": path,
            "headers": headers,
            "body": None
        }

    # Log failure for debugging
    if logger:
        # Truncate for logging
        truncated = original[:200] + "..." if len(original) > 200 else original
        logger.debug(f"Failed to extract JSON from: {truncated}")

    return None


def fix_json_string(json_str: str) -> str:
    """
    Attempt to fix common JSON formatting issues.

    Args:
        json_str: Potentially malformed JSON string

    Returns:
        Fixed JSON string
    """
    fixed = json_str

    # Replace single quotes with double quotes (common LLM mistake)
    # But be careful not to replace inside strings
    fixed = re.sub(r"(?<![\"\\])'([^']*)'(?![\"\\])", r'"\1"', fixed)

    # Fix unquoted property names
    fixed = re.sub(r'(\{|\,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', fixed)

    # Remove trailing commas before } or ]
    fixed = re.sub(r',\s*([}\]])', r'\1', fixed)

    # Fix null/true/false that might be quoted incorrectly
    fixed = re.sub(r'"(null|true|false)"', lambda m: m.group(1), fixed)

    # Remove any control characters
    fixed = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', fixed)

    return fixed


@dataclass
class LLMResponse:
    """Data class for LLM response."""
    content: str
    model: str
    tokens_used: int
    generation_time: float
    success: bool
    error: Optional[str] = None


class OllamaClient:
    """
    Client for interacting with Ollama API.

    Provides methods for generating fuzzing payloads using LLM.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "qwen3:8b",
        timeout: int = 120,
        max_retries: int = 3,
        temperature: float = 0.7,
        max_tokens: int = 512,
        keep_alive: str = "5m",
        log_level: str = "INFO"
    ):
        """
        Initialize the Ollama client.

        Args:
            base_url: Ollama API base URL
            model: Model name to use
            timeout: Request timeout in seconds (default 120 for slower hardware)
            max_retries: Maximum retry attempts
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate (reduced for faster response)
            keep_alive: How long to keep model in memory (e.g., "5m", "1h")
            log_level: Logging level
        """
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.keep_alive = keep_alive

        self.logger = setup_logging(name="OllamaClient", log_level=log_level)

        # Track usage statistics
        self._total_requests = 0
        self._total_tokens = 0
        self._total_time = 0.0
        self._errors = 0

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> LLMResponse:
        """
        Generate text using the LLM.

        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            temperature: Override default temperature
            max_tokens: Override default max tokens

        Returns:
            LLMResponse with generated content
        """
        self._total_requests += 1
        start_time = time.time()

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": temperature or self.temperature,
                "num_predict": max_tokens or self.max_tokens,
                "num_ctx": 2048,  # context window size
            }
        }

        if system_prompt:
            payload["system"] = system_prompt

        # Log at INFO level so user can see LLM is working
        if self._total_requests % 5 == 1:  # Log every 5th request to avoid spam
            self.logger.info(f"LLM request #{self._total_requests} (this may take 10-30s)...")

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=self.timeout
                )
                response.raise_for_status()

                data = response.json()
                generation_time = time.time() - start_time
                self._total_time += generation_time

                # Extract token count if available
                tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
                self._total_tokens += tokens

                return LLMResponse(
                    content=data.get("response", ""),
                    model=self.model,
                    tokens_used=tokens,
                    generation_time=generation_time,
                    success=True
                )

            except requests.exceptions.Timeout:
                self.logger.warning(f"Request timed out (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff

            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                break

        self._errors += 1
        return LLMResponse(
            content="",
            model=self.model,
            tokens_used=0,
            generation_time=time.time() - start_time,
            success=False,
            error="Max retries exceeded"
        )

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> LLMResponse:
        """
        Chat with the LLM using message history.

        Args:
            messages: List of message dictionaries with 'role' and 'content'
            temperature: Override default temperature
            max_tokens: Override default max tokens

        Returns:
            LLMResponse with generated content
        """
        self._total_requests += 1
        start_time = time.time()

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "keep_alive": self.keep_alive,
            "options": {
                "temperature": temperature or self.temperature,
                "num_predict": max_tokens or self.max_tokens,
                "num_ctx": 2048,
            }
        }

        self.logger.debug(f"Sending chat request to Ollama (timeout={self.timeout}s)...")

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    timeout=self.timeout
                )
                response.raise_for_status()

                data = response.json()
                generation_time = time.time() - start_time
                self._total_time += generation_time

                # Extract content from message
                content = data.get("message", {}).get("content", "")

                # Extract token count
                tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)
                self._total_tokens += tokens

                return LLMResponse(
                    content=content,
                    model=self.model,
                    tokens_used=tokens,
                    generation_time=generation_time,
                    success=True
                )

            except requests.exceptions.Timeout:
                self.logger.warning(f"Chat request timed out (attempt {attempt + 1}/{self.max_retries})")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

            except requests.exceptions.RequestException as e:
                self.logger.error(f"Chat request failed: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)

            except Exception as e:
                self.logger.error(f"Unexpected error in chat: {e}")
                break

        self._errors += 1
        return LLMResponse(
            content="",
            model=self.model,
            tokens_used=0,
            generation_time=time.time() - start_time,
            success=False,
            error="Max retries exceeded"
        )

    def is_available(self) -> bool:
        """
        Check if Ollama is available and the model is loaded.

        Returns:
            True if available
        """
        try:
            response = requests.get(
                f"{self.base_url}/api/tags",
                timeout=10
            )
            response.raise_for_status()

            data = response.json()
            models = [m.get("name", "") for m in data.get("models", [])]

            # Check if our model is available
            model_base = self.model.split(":")[0]
            for m in models:
                if model_base in m:
                    return True

            self.logger.warning(f"Model {self.model} not found. Available: {models}")
            return False

        except Exception as e:
            self.logger.error(f"Failed to check Ollama availability: {e}")
            return False

    def warmup(self) -> bool:
        """
        Warm up the model by sending a simple request.
        This pre-loads the model into memory to avoid timeout on first real request.

        Returns:
            True if warmup successful
        """
        self.logger.info(f"Warming up model {self.model}...")

        try:
            # Send a minimal request to load the model
            payload = {
                "model": self.model,
                "prompt": "Hi",
                "stream": False,
                "keep_alive": self.keep_alive,
                "options": {
                    "num_predict": 1,  # Minimal output
                }
            }

            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=180  # Longer timeout for initial load
            )
            response.raise_for_status()

            self.logger.info(f"Model {self.model} warmed up successfully")
            return True

        except requests.exceptions.Timeout:
            self.logger.error("Model warmup timed out (180s). Model may need more time to load.")
            return False
        except Exception as e:
            self.logger.error(f"Model warmup failed: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        avg_time = self._total_time / self._total_requests if self._total_requests > 0 else 0

        return {
            "total_requests": self._total_requests,
            "total_tokens": self._total_tokens,
            "total_time": self._total_time,
            "average_time": avg_time,
            "errors": self._errors,
            "model": self.model
        }

    def reset_stats(self):
        """Reset usage statistics."""
        self._total_requests = 0
        self._total_tokens = 0
        self._total_time = 0.0
        self._errors = 0


class FuzzingPrompts:
    """Collection of prompts for fuzzing with LLM - optimized for qwen3."""

    # System prompts - very short and direct
    SEED_GENERATION_SYSTEM = "Output valid JSON only. No explanation."

    SEED_GENERATION_PROMPT = """/no_think
Generate HTTP attack payload. Output JSON only.

Example: {"method":"GET","path":"/../etc/passwd","headers":{"Host":"127.0.0.1"},"body":null}

Your payload (JSON only):"""

    MUTATION_SYSTEM = "Output valid JSON only. No explanation."

    MUTATION_PROMPT_TEMPLATE = """/no_think
Mutate this request: {original_request}

Example output: {{"method":"GET","path":"/../etc/passwd","headers":{{"Host":"x"}},"body":null}}

Your mutation (JSON only):"""

    FEEDBACK_SYSTEM = "Output valid JSON only. No explanation."

    FEEDBACK_PROMPT_TEMPLATE = """/no_think
Stats: {iterations} iterations, {crashes} crashes, CVEs: {cve_triggers}

Example: {{"focus_attack_types":["path_traversal"],"target_paths":["/admin"],"priority_headers":["X-Forwarded-For"]}}

Your suggestion (JSON only):"""

    @staticmethod
    def get_seed_prompt(context: Optional[Dict[str, Any]] = None) -> str:
        """Get seed generation prompt with optional context."""
        return """/no_think
Generate HTTP attack payload. Output JSON only.

Example: {"method":"GET","path":"/../etc/passwd","headers":{"Host":"127.0.0.1"},"body":null}

Your payload (JSON only):"""

    @staticmethod
    def get_mutation_prompt(payload: Dict[str, Any]) -> str:
        """Get mutation prompt for a specific payload."""
        original = json.dumps(payload)
        return f"""/no_think
Mutate this: {original}

Example: {{"method":"GET","path":"/../etc/passwd","headers":{{"Host":"x"}},"body":null}}

Your mutation (JSON only):"""

    @staticmethod
    def get_feedback_prompt(
        iterations: int,
        crashes: int,
        cve_triggers: Dict[str, int],
        error_rate: float,
        recent_responses: List[str]
    ) -> str:
        """Get feedback analysis prompt."""
        return f"""/no_think
Stats: {iterations} iterations, {crashes} crashes, CVEs: {cve_triggers}

Example: {{"focus_attack_types":["type"],"target_paths":["/path"],"priority_headers":["Header"]}}

Your suggestion (JSON only):"""
