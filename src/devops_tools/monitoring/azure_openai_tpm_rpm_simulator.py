#!/usr/bin/env python3
"""
Azure OpenAI TPM/RPM simulator.

- Sends N chat requests to a single deployment.
- Prints x-ratelimit-* headers, HTTP status, and usage.
- Lets you vary max_tokens and pacing to see throttling behavior.

Env vars:
  AOAI_ENDPOINT=https://<your-resource>.openai.azure.com
  AOAI_API_KEY=<key>
  AOAI_DEPLOYMENT=<deployment-name>
  AOAI_API_VERSION=2024-02-15-preview   # or your chosen preview/stable version
"""

import os
import time
import json
import requests

PROMPT = "Write a detailed essay on the impact of artificial intelligence on modern society. Cover the following points:\n\n1. Introduction to artificial intelligence and its historical development.\n2. The various applications of AI in different sectors such as healthcare, finance, education, and transportation.\n3. The benefits of AI, including increased efficiency, accuracy, and the potential for innovation.\n4. The ethical considerations and potential risks associated with AI, including issues of privacy, job displacement, and decision-making biases.\n5. The future of AI, including emerging technologies, potential advancements, and their implications for society.\n6. Conclude with a balanced view on how society can best leverage AI while addressing its challenges."

# -------- configurable knobs --------
TOTAL_CALLS = 6  # Number of requests to send
SPACING_SECONDS = 10  # Time between requests
MAX_TOKENS = 800  # Maximum tokens for completion
N_CHOICES = 1  # Number of choices per request
BEST_OF = 1  # Best-of multiplier if supported
TEMPERATURE = 0.7
TIMEOUT_SEC = 60
PRINT_BODY_SNIPPET = False  # Set True to see part of the model output
# ------------------------------------

EP = os.environ["AOAI_ENDPOINT"].rstrip("/")
KEY = os.environ["AOAI_API_KEY"]
DEP = os.environ["AOAI_DEPLOYMENT"]
VER = os.getenv("AOAI_API_VERSION", "2024-02-15-preview")

URL = f"{EP}/openai/deployments/{DEP}/chat/completions?api-version={VER}"
HEAD = {"api-key": KEY, "Content-Type": "application/json"}


def safe_get(d, k, default=None):
    return d.get(k, default) if d else default


def one_call(session: requests.Session, i: int):
    body = {
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": PROMPT},
        ],
        "temperature": TEMPERATURE,
        "n": N_CHOICES,
        "max_tokens": MAX_TOKENS,
    }

    t0 = time.time()
    resp = session.post(URL, headers=HEAD, data=json.dumps(body), timeout=TIMEOUT_SEC)
    dt = time.time() - t0

    h = {k.lower(): v for k, v in resp.headers.items()}
    status = resp.status_code
    try:
        data = resp.json()
    except Exception:
        data = {}

    usage = safe_get(data, "usage", {})
    prompt_used = int(safe_get(usage, "prompt_tokens", 0))
    completion_used = int(safe_get(usage, "completion_tokens", 0))
    total_used = int(safe_get(usage, "total_tokens", 0))

    # Rate-limit headers (case-insensitive)
    r_req_lim = safe_get(h, "x-ratelimit-limit-requests")
    r_req_rem = safe_get(h, "x-ratelimit-remaining-requests")
    r_req_rst = safe_get(h, "x-ratelimit-reset-requests")
    r_tok_lim = safe_get(h, "x-ratelimit-limit-tokens")
    r_tok_rem = safe_get(h, "x-ratelimit-remaining-tokens")
    r_tok_rst = safe_get(h, "x-ratelimit-reset-tokens")
    retry = safe_get(h, "retry-after")

    print(f"\n== Call {i} | HTTP {status} | {dt:.2f}s ==")
    print(f"usage  prompt={prompt_used} completion={completion_used} total={total_used}")
    print(f"RPM    limit={r_req_lim} remaining={r_req_rem} reset_s={r_req_rst}")
    print(f"TPM    limit={r_tok_lim} remaining={r_tok_rem} reset_s={r_tok_rst}")
    if retry:
        print(f"retry-after={retry}s")

    if status == 429:
        # Helpful error text if available
        err = safe_get(data, "error") or data
        print(f"THROTTLED: {err}")
    elif PRINT_BODY_SNIPPET:
        # Show a small slice of the model output
        try:
            txt = data["choices"][0]["message"]["content"]
            print(f"body: {txt[:160].replace('\\n',' ')} …")
        except Exception:
            pass


def main():
    print("Starting Azure OpenAI TPM/RPM simulation...")

    with requests.Session() as s:
        for i in range(1, TOTAL_CALLS + 1):
            one_call(s, i)
            if i < TOTAL_CALLS and SPACING_SECONDS > 0:
                time.sleep(SPACING_SECONDS)


if __name__ == "__main__":
    main()
