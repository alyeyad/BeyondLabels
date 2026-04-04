# runner.py
import os
from typing import Tuple

from openai import OpenAI
import tiktoken

import transformers
# ========== CONFIGURATION ==========

OUTPUT_DIR = "model_outputs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Supported platforms: gpt, deepseek, qwen
MODEL_PROVIDERS = {
    "openai": {
        "api_key_env": "OPENAI_API_KEY",
        "base_url": None
    },
    "deepseek": {
        "api_key_env": "DEEPSEEK_API_KEY",
        "base_url": "https://api.deepseek.com"
    },
    "qwen": {
        "api_key_env": "ALIBABA_API_KEY",
        "base_url": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    }
}

MODEL_TOKEN_LIMITS = {
  "qwen-plus": 98_304,
    "qwen-plus-2025-04-28": 98_304,
  "deepseek-reasoner": 65_536,
  "gpt-4o": 128_000,
  "gpt-4.1": 1_000_000,
   "o3": 200_000,
    "gpt-3.5-turbo-0125": 16_000
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
    if "gpt" in model or "o3" in model:
        encoding = tiktoken.encoding_for_model("gpt-4o")
        token_count = len(encoding.encode(context + user_input))
    else:
        if "deepseek" in model:
            chat_tokenizer_dir = r"/home/alye/Git/log4j-project/large-language-models/experiments-code/llm_runner/deepseek-tokenizer"
        elif "qwq" in model or "qwen" in model:
            chat_tokenizer_dir = r"/home/alye/Git/log4j-project/large-language-models/experiments-code/llm_runner/qwq-tokenizer"

        tokenizer = transformers.AutoTokenizer.from_pretrained(
            chat_tokenizer_dir, trust_remote_code=True
        )

        result = tokenizer.encode(context + user_input)
        token_count = len(result)
    return token_count


# ========== GPT CALL ==========
def send_prompt(client: OpenAI, context: str, user_input: str, model: str,
                temperature: float = 0.0, max_tokens: int = 131000,
                enable_thinking: bool = False, stream: bool = False) -> Tuple[str, str]:
    messages = [
        {"role": "system", "content": context},
        {"role": "user", "content": user_input},
    ]

    extra = {"extra_body": {"enable_thinking": True}} if enable_thinking else {}
    if "qwq" in model or "qwen" in model:
        completion = client.chat.completions.create(
            model="qwen-plus-2025-04-28",  # You can replace it with other deep thinking models as needed
            messages=messages,
            # enable_thinking parameter opens the thinking process, this parameter is invalid for QwQ models
            extra_body={"enable_thinking": True},
            stream=True,
            # stream_options={
            #     "include_usage": True
            # },
        )
        reasoning_content = ""  # Complete reasoning process
        answer_content = ""  # Complete response
        is_answering = False  # Whether entering the response phase
        print("\n" + "=" * 20 + "Thinking Process" + "=" * 20 + "\n")

        for chunk in completion:
            if not chunk.choices:
                print("\nUsage:")
                print(chunk.usage)
                continue

            delta = chunk.choices[0].delta

            # Only collect reasoning content
            if hasattr(delta, "reasoning_content") and delta.reasoning_content is not None:
                if not is_answering:
                    print(delta.reasoning_content, end="", flush=True)
                reasoning_content += delta.reasoning_content

            # Received content, starting to respond
            if hasattr(delta, "content") and delta.content:
                if not is_answering:
                    print("\n" + "=" * 20 + "Complete Response" + "=" * 20 + "\n")
                    is_answering = True
                print(delta.content, end="", flush=True)
                answer_content += delta.content
    elif model == "gpt-5" or model=="o3":
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            # temperature=temperature,
            # max_tokens=max_tokens,
            stream=False,
            reasoning_effort="high",
            verbosity="high",
            **extra
        )
        answer_content = response.choices[0].message.content
        try:
            reasoning_content = response.choices[0].message.reasoning_content
        except Exception as e:
            # print("No reasoning content:", e)
            reasoning_content = ""
    elif "gpt-5.2" in model:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.0,
            max_completion_tokens=128_000,
            stream=False,
            **extra
        )
        answer_content = response.choices[0].message.content
        try:
            reasoning_content = response.choices[0].message.reasoning_content
        except Exception as e:
            # print("No reasoning content:", e)
            reasoning_content = ""
    else:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.0,
            # max_tokens=max_tokens,
            stream=False,
            # reasoning_effort="high",
            # verbosity="high",
            **extra
        )
        answer_content = response.choices[0].message.content
        try:
            reasoning_content = response.choices[0].message.reasoning_content
        except Exception as e:
            # print("No reasoning content:", e)
            reasoning_content = ""



    return answer_content, reasoning_content

def get_max_tokens(model: str) -> int:
    return MODEL_TOKEN_LIMITS[model]