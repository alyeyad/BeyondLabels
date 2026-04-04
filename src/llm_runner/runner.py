# runner.py
import os
from typing import Tuple

from openai import OpenAI
import tiktoken

import transformers
# ========== CONFIGURATION ==========

OUTPUT_DIR = "model_outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Supported platforms: gpt, deepseek
MODEL_PROVIDERS = {
    "openai": {
        "api_key_env": "OPENAI_API_KEY",
        "base_url": None
    },
    "deepseek": {
        "api_key_env": "DEEPSEEK_API_KEY",
        "base_url": "https://api.deepseek.com"
    }
}

# ========== CLIENT INITIALIZATION ==========
def setup_client(provider: str) -> OpenAI:
    if provider not in MODEL_PROVIDERS:
        raise ValueError(f"Unsupported provider: {provider}")
    info = MODEL_PROVIDERS[provider]
    api_key = os.getenv(info["api_key_env"])
    return OpenAI(api_key=api_key, base_url=info["base_url"])

# ========== TOKEN COUNT ==========
def count_tokens(model: str, context: str, user_input: str) -> int:
    token_count = None
    if "gpt" in model:
        encoding = tiktoken.encoding_for_model(model)
        token_count = len(encoding.encode(context + user_input))
    else:
        if "deepseek" in model:
            chat_tokenizer_dir = r"deepseek-tokenizer"

        tokenizer = transformers.AutoTokenizer.from_pretrained(
            chat_tokenizer_dir, trust_remote_code=True
        )

        result = tokenizer.encode(context + user_input)
        token_count = len(result)
    return token_count


# ========== GPT CALL ==========
def send_prompt(client: OpenAI, context: str, user_input: str, model: str,
                enable_thinking: bool = False) -> Tuple[str, str]:
    messages = [
        {"role": "system", "content": context},
        {"role": "user", "content": user_input},
    ]

    extra = {"extra_body": {"enable_thinking": True}} if enable_thinking else {}
    if model.startswith("gpt-5"):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            stream=False,
            reasoning_effort="high",
            verbosity="high",
            **extra
        )
        answer_content = response.choices[0].message.content
        try:
            reasoning_content = response.choices[0].message.reasoning_content
        except Exception as e:
            reasoning_content = ""
    else:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.0,
            stream=False,
            **extra
        )
        answer_content = response.choices[0].message.content
        try:
            reasoning_content = response.choices[0].message.reasoning_content
        except Exception:
            reasoning_content = ""

    return answer_content, reasoning_content