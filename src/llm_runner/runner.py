# runner.py
import os
from typing import Tuple

from openai import OpenAI
import anthropic

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

def extract_text(message):
    return "".join(
        block.text
        for block in message.content
        if block.type == "text"
    )

# ========== GPT CALL ==========
def send_prompt(client, context: str, user_input: str, model: str,
                enable_thinking: bool = False):
    messages = [
        {"role": "system", "content": context},
        {"role": "user", "content": user_input},
    ]
    usage = None
    answer_content = ""
    reasoning_content = ""
    extra = {"extra_body": {"enable_thinking": True}} if enable_thinking else {}
    if "claude" in model:
        with client.messages.stream(
                model=model,
                temperature=0.0,
                system=context,
                max_tokens=64_000,
                messages=[
                    {
                        "role": "user",
                        "content": user_input
                    }
                ]
        ) as stream:
            stream.until_done()

            final_message = stream.get_final_message()
            if final_message:
                answer_content = extract_text(final_message)
                usage_data = final_message.usage
                input_tokens = usage_data.input_tokens
                output_tokens = usage_data.output_tokens
                total_tokens = input_tokens + output_tokens
                usage = {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "total_tokens": total_tokens
                }
    elif model.startswith("gpt-5"):
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
    elif "llama" in model:
        response = client.chat.completions.create(
            model=model,
            temperature=0.0,
            response_format={"type": "json_object"},
            messages=messages
        )
        answer_content = response.choices[0].message.content
        reasoning_content = ""
        input_tokens = response.usage.prompt_tokens
        output_tokens = response.usage.completion_tokens
        total_tokens = input_tokens + output_tokens
        usage = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens
        }
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
    return answer_content, reasoning_content, usage