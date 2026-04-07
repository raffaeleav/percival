import os
import requests


def get_token():
    token = os.getenv("HF_TOKEN")

    return token


def query_hf(api_token, prompt, findings, max_tokens=400):
    url = "https://router.huggingface.co/featherless-ai/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    full_prompt = f"{prompt}\n\n{findings}"

    payload = {
        "model": "meta-llama/Meta-Llama-3.1-8B-Instruct",
        "messages": [
            {"role": "system", "content": prompt},
            {"role": "user", "content": findings}
        ],
        "max_tokens": max_tokens,
        "stream": False,
    }

    try:
        response = requests.post(
            url, 
            headers=headers, 
            json=payload
        )

        if response.status_code == 402:
            raise RuntimeError("Your Huggingface Inference Providers credits are expired! It is not possible to generate a written report")
        
        response.raise_for_status()
    except Exception:
        raise

    completion = response.json()

    return completion["choices"][0]["message"]["content"]
