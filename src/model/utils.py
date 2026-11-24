import json
import os
from pathlib import Path

import openai
import google.generativeai as genai

# Optional local configuration is ignored by Git. Environment variables take precedence.
_local_path = Path(__file__).with_name("local_config.json")
_local_config = json.loads(_local_path.read_text()) if _local_path.exists() else {}
_env_keys = os.environ.get("OPENAI_API_KEY", "")
standard_keys = (
    [key for key in _env_keys.split(":") if key]
    if _env_keys
    else _local_config.get("standard_keys", [""])
)
openai_base_url = os.environ.get(
    "OPENAI_BASE_URL", _local_config.get("openai_base_url", "https://api.openai.com/v1")
)

# Replicate reads REPLICATE_API_TOKEN from the environment when used.

# Gemini API
genai.configure(api_key=os.environ.get("GEMINI_KEY"))

# Iterative count bound
iterative_count_bound = 3

# Scope count bound (for development)
scope_count_bound = 10
