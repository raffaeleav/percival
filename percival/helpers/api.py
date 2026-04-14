import os

from huggingface_hub import InferenceClient


def get_token():
    token = os.getenv("HF_TOKEN")

    return token


def get_hf_client(api_token):
    client = InferenceClient(
        api_key=api_token,
    )

    return client


def query_hf(client, prompt, findings, max_tokens=400):
    try:
        completion = client.chat.completions.create(
            model="Qwen/Qwen2.5-7B-Instruct:together-ai",
            max_tokens=max_tokens,
            messages=[
                {
                    "role": "system", 
                    "content": prompt
                },
                {
                    "role": "user", 
                    "content": str(findings)
                }
            ],
        )

        return completion.choices[0].message
    except Exception:
        raise

"""
def query_hf(api_token, prompt, findings, max_tokens=400):
    url = "https://router.huggingface.co/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": "Qwen/Qwen2.5-7B-Instruct:featherless-ai",
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
"""