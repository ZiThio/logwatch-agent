from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request


class OllamaError(RuntimeError):
    pass


DEFAULT_TIMEOUT_SECONDS = 120.0
# How long Ollama keeps a model in memory after a request. Ollama's own default
# is 5 minutes; alerts are often further apart, and reloading a model on a
# CPU-only machine can take longer than the request timeout.
DEFAULT_KEEP_ALIVE = "30m"


class OllamaClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434",
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        keep_alive: str = DEFAULT_KEEP_ALIVE,
    ):
        if timeout <= 0:
            raise ValueError("Ollama timeout must be greater than zero")
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme != "http" or parsed.port is None:
            raise ValueError("Ollama URL must be an explicit local HTTP URL, e.g. http://127.0.0.1:11434")
        host = parsed.hostname or ""
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host.lower() == "localhost"
        if not is_loopback:
            raise ValueError("For privacy, Ollama must be hosted on this computer (loopback only)")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.keep_alive = keep_alive

    def _post(self, endpoint: str, payload: dict[str, object]) -> dict[str, object]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}{endpoint}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OllamaError(f"Ollama request failed: {exc}") from exc
        if not isinstance(result, dict):
            raise OllamaError("Ollama returned an unexpected response")
        return result

    def embed(self, model: str, texts: list[str]) -> list[list[float]]:
        result = self._post(
            "/api/embed",
            {"model": model, "input": texts, "keep_alive": self.keep_alive},
        )
        embeddings = result.get("embeddings")
        if not isinstance(embeddings, list) or len(embeddings) != len(texts):
            raise OllamaError("Ollama returned an invalid embedding response")
        try:
            return [[float(value) for value in vector] for vector in embeddings]
        except (TypeError, ValueError) as exc:
            raise OllamaError("Ollama returned malformed embedding values") from exc

    def chat_json(self, model: str, system: str, prompt: str) -> dict[str, object]:
        result = self._post(
            "/api/chat",
            {
                "model": model,
                "stream": False,
                # Skip the reasoning phase of "thinking" models such as qwen3:
                # it is slow and not needed for a short structured answer.
                # Models without a thinking mode accept and ignore this flag.
                "think": False,
                "keep_alive": self.keep_alive,
                "format": "json",
                "options": {"temperature": 0.2},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        message = result.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        try:
            parsed = json.loads(content) if isinstance(content, str) else None
        except json.JSONDecodeError as exc:
            raise OllamaError("Ollama returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise OllamaError("Ollama response must be a JSON object")
        return parsed
