# runner.py
import os
import random
import time
from typing import Optional, Tuple

from openai import OpenAI
import anthropic

import tiktoken

# ========== TRANSIENT-FAILURE RETRY ==========
# Providers return 429/5xx under load (e.g. Anthropic "overloaded_error", 529).
# Without a retry the caller drops the run, leaving a CVE with fewer than the
# requested number of runs and biasing its median.
RETRY_MAX_ATTEMPTS = int(os.getenv("LLM_MAX_ATTEMPTS", "6"))
RETRY_BASE_DELAY = float(os.getenv("LLM_RETRY_BASE_DELAY", "5"))
RETRY_MAX_DELAY = float(os.getenv("LLM_RETRY_MAX_DELAY", "120"))

_RETRY_STATUS_CODES = {408, 409, 429, 500, 502, 503, 504, 529}
_RETRY_MARKERS = (
    "overloaded",
    "rate limit",
    "rate_limit",
    "timeout",
    "timed out",
    "temporarily unavailable",
    "service unavailable",
    "internal server error",
    "connection error",
    "connection reset",
    "bad gateway",
    "returned no choices",
)


def is_transient_error(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    if isinstance(status, int) and status in _RETRY_STATUS_CODES:
        return True
    text = str(exc).lower()
    if any(marker in text for marker in _RETRY_MARKERS):
        return True
    return any(str(code) in text for code in (429, 529, 503, 502, 504))

# ========== CONFIGURATION ==========
# Supported platforms: gpt, deepseek
MODEL_PROVIDERS = {
    "openai": {
        "api_key_env": "OPENAI_API_KEY",
        "base_url": None
    },
    "deepseek": {
        "api_key_env": "DEEPSEEK_API_KEY",
        "base_url": "https://api.deepseek.com"
    },
    "anthropic": {
        "api_key_env": "ANTHROPIC_API_KEY",
        "base_url": None
    },
    "openrouter": {
        "api_key_env": "OPENROUTER_API_KEY",
        "base_url": "https://openrouter.ai/api/v1"
    }
}


# ========== CLIENT INITIALIZATION ==========
def setup_client(provider: str):
    if provider not in MODEL_PROVIDERS:
        raise ValueError(f"Unsupported provider: {provider}")
    elif provider == "anthropic":
        return anthropic.Anthropic()
    info = MODEL_PROVIDERS[provider]
    api_key = os.getenv(info["api_key_env"])
    return OpenAI(api_key=api_key, base_url=info["base_url"])


# Claude Sonnet 4.5: Messages API defaults (no extended thinking).
DEFAULT_CLAUDE_MAX_TOKENS = 64_000


def extract_text(message):
    return "".join(
        block.text
        for block in message.content
        if block.type == "text"
    )


def is_deepseek_v32(model: str) -> bool:
    """OpenRouter DeepSeek-V3.2 (thinking via ``reasoning.enabled``)."""
    m = model.lower()
    return "deepseek-v3.2" in m


def extract_openrouter_reasoning(message) -> str:
    """Pull thinking text from OpenRouter reasoning fields."""
    reasoning = getattr(message, "reasoning", None)
    if reasoning:
        return reasoning
    details = getattr(message, "reasoning_details", None) or []
    parts = []
    for item in details:
        if isinstance(item, dict):
            text = item.get("text") or item.get("content")
        else:
            text = getattr(item, "text", None) or getattr(item, "content", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


def is_reasoning_model(model: str) -> bool:
    """Reasoning models reject a sampling temperature; callers should pass
    ``temperature=None`` for these so it is omitted from the request."""
    m = model.lower()
    return (
        m.startswith("gpt-5")
        or m == "o3"
        or m.startswith("o3-")
        or "reasoner" in m
        or m.startswith("o1")
        or is_deepseek_v32(model)
    )


# ========== GPT CALL ==========
def send_prompt(client, context: str, user_input: str, model: str,
                enable_thinking: bool = False,
                temperature: Optional[float] = 0.0,
                seed: Optional[int] = None,
                max_attempts: int = RETRY_MAX_ATTEMPTS):
    """Run a single generation, retrying transient provider failures.

    Retries use exponential backoff with jitter. Non-transient errors (bad
    request, auth, context-length) propagate immediately so they are not
    silently retried. The sampling parameters are unchanged across attempts, so
    a retried run is equivalent to the one that failed.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(1, max(1, max_attempts) + 1):
        try:
            return _send_prompt_once(
                client, context, user_input, model,
                enable_thinking=enable_thinking,
                temperature=temperature,
                seed=seed,
            )
        except Exception as exc:
            last_exc = exc
            if attempt >= max_attempts or not is_transient_error(exc):
                raise
            delay = min(RETRY_BASE_DELAY * (2 ** (attempt - 1)), RETRY_MAX_DELAY)
            delay += random.uniform(0, delay * 0.25)
            print(
                f"  [RETRY {attempt}/{max_attempts - 1}] transient failure "
                f"({type(exc).__name__}); sleeping {delay:.1f}s",
                flush=True,
            )
            time.sleep(delay)
    raise last_exc  # pragma: no cover - loop always returns or raises


def _send_prompt_once(client, context: str, user_input: str, model: str,
                      enable_thinking: bool = False,
                      temperature: Optional[float] = 0.0,
                      seed: Optional[int] = None):
    """Run a single generation.

    ``temperature`` is forwarded when not None (omitted for reasoning models).
    ``seed`` is forwarded only for OpenAI-family chat models that accept it.
    DeepSeek-V3.2 on OpenRouter (``deepseek/deepseek-v3.2``) enables thinking via
    ``extra_body.reasoning.enabled`` and stores the chain-of-thought in
    ``reasoning_content`` (from ``message.reasoning`` / ``reasoning_details``).
    The returned ``usage`` dict is augmented with the sampling parameters that
    were actually used (``temperature_used``, ``seed_used``,
    ``system_fingerprint``, ``model_returned``) so multi-run variance (E2) is
    fully auditable from the logs.
    """
    messages = [
        {"role": "system", "content": context},
        {"role": "user", "content": user_input},
    ]
    usage = None
    answer_content = ""
    reasoning_content = ""
    extra = {"extra_body": {"enable_thinking": True}} if enable_thinking else {}

    # ``seed`` is only supported by OpenAI-family chat models.
    seed_kwargs = {}
    if seed is not None and ("gpt" in model or model == "o3"):
        seed_kwargs["seed"] = seed
    # ``temperature`` omitted entirely when None (reasoning models).
    temp_kwargs = {}
    if temperature is not None:
        temp_kwargs["temperature"] = temperature

    response = None
    served_model = None
    temp_sent = None
    reasoning_effort_used = None
    reasoning_enabled = None
    if "claude" in model:
        # Anthropic streaming has been observed to return stop_reason="refusal"
        # with empty text / output_tokens=1 on prompts that succeed via
        # messages.create (broke several CVEPath_obf Claude cells). The SDK
        # forbids non-streaming when max_tokens is huge (expected >10 min), so
        # use a practical findings-sized cap for create, and only stream as a
        # secondary attempt.
        temp_sent = temp_kwargs.get("temperature")
        claude_max = min(DEFAULT_CLAUDE_MAX_TOKENS, 16_384)
        final_message = client.messages.create(
            model=model,
            system=context,
            max_tokens=claude_max,
            messages=[{"role": "user", "content": user_input}],
            timeout=600.0,
            **temp_kwargs,
        )
        answer_content = extract_text(final_message) or ""
        stop_reason = getattr(final_message, "stop_reason", None)
        if not answer_content.strip():
            with client.messages.stream(
                model=model,
                system=context,
                max_tokens=DEFAULT_CLAUDE_MAX_TOKENS,
                messages=[{"role": "user", "content": user_input}],
                **temp_kwargs,
            ) as stream:
                stream.until_done()
                streamed = stream.get_final_message()
            if streamed is not None:
                streamed_text = extract_text(streamed) or ""
                if streamed_text.strip():
                    final_message = streamed
                    answer_content = streamed_text
                    stop_reason = getattr(final_message, "stop_reason", None)
        served_model = getattr(final_message, "model", None)
        usage_data = final_message.usage
        usage = {
            "input_tokens": usage_data.input_tokens,
            "output_tokens": usage_data.output_tokens,
            "total_tokens": usage_data.input_tokens + usage_data.output_tokens,
            "stop_reason": stop_reason,
        }
    elif model.startswith("gpt-5"):
        # Reasoning model: no sampling temperature; effort fixed to high.
        reasoning_effort_used = "high"
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            stream=False,
            reasoning_effort=reasoning_effort_used,
            **seed_kwargs,
            **extra
        )
        # Providers occasionally return content=None; coerce so callers never see None.
        answer_content = response.choices[0].message.content or ""
        try:
            reasoning_content = response.choices[0].message.reasoning_content
        except Exception:
            pass
        try:
            usage_data = response.usage
            usage = {
                "input_tokens": usage_data.prompt_tokens,
                "output_tokens": usage_data.completion_tokens,
                "total_tokens": usage_data.total_tokens
            }
        except:
            usage = None
            pass
    elif is_deepseek_v32(model):
        # OpenRouter DeepSeek-V3.2: enable thinking; omit temperature.
        reasoning_enabled = True
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            stream=False,
            extra_body={"reasoning": {"enabled": True}},
            **seed_kwargs,
        )
        message = response.choices[0].message
        answer_content = message.content or ""
        reasoning_content = extract_openrouter_reasoning(message)
        try:
            usage_data = response.usage
            usage = {
                "input_tokens": usage_data.prompt_tokens,
                "output_tokens": usage_data.completion_tokens,
                "total_tokens": usage_data.total_tokens,
            }
            details = getattr(usage_data, "completion_tokens_details", None)
            if details is not None:
                usage["reasoning_tokens"] = getattr(details, "reasoning_tokens", None)
        except Exception:
            usage = None
    elif "llama" in model:
        temp_sent = temp_kwargs.get("temperature")
        response = client.chat.completions.create(
            model=model,
            response_format={"type": "json_object"},
            messages=messages,
            **temp_kwargs,
            **seed_kwargs
        )
        # OpenRouter Llama sometimes returns content=None (esp. under json_object)
        # or an empty choices list; coerce / raise so callers get a clean failure.
        choices = getattr(response, "choices", None) or []
        if not choices:
            raise RuntimeError(
                f"Llama/OpenRouter returned no choices (model={model})"
            )
        answer_content = (choices[0].message.content or "") if choices[0].message else ""
        reasoning_content = ""
        usage_data = getattr(response, "usage", None)
        if usage_data is None:
            usage = None
        else:
            input_tokens = usage_data.prompt_tokens
            output_tokens = usage_data.completion_tokens
            total_tokens = input_tokens + output_tokens
            usage = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens
            }
    else:
        temp_sent = temp_kwargs.get("temperature")
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            stream=False,
            **temp_kwargs,
            **seed_kwargs,
            **extra
        )
        answer_content = response.choices[0].message.content or ""
        try:
            reasoning_content = response.choices[0].message.reasoning_content
        except:
            pass
        try:
            usage_data = response.usage
            usage = {
                "input_tokens": usage_data.prompt_tokens,
                "output_tokens": usage_data.completion_tokens,
                "total_tokens": usage_data.total_tokens
            }
        except:
            usage = None
            pass

    if usage is None:
        usage = {}
    usage["temperature_used"] = temp_sent
    usage["seed_used"] = seed_kwargs.get("seed")
    usage["reasoning_effort_used"] = reasoning_effort_used
    usage["reasoning_enabled"] = reasoning_enabled
    usage["system_fingerprint"] = (
        getattr(response, "system_fingerprint", None) if response is not None else None
    )
    usage["model_returned"] = (
        getattr(response, "model", None) if response is not None else served_model
    )
    return answer_content, reasoning_content, usage
