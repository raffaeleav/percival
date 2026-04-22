import os

from huggingface_hub import InferenceClient


def get_token():
    token = os.getenv("HF_TOKEN")

    return token


def get_hf_client(api_token):
    client = InferenceClient(api_key=api_token,)

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
