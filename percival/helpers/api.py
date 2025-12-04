import os
import time
import requests

from percival.helpers import folders as fld


def query_osv(batch):
    delay = 30
    url = "https://api.osv.dev/v1/querybatch"
    queries = [
        {"package": {"name": item["name"]}, "version": item["version"]}
        for item in batch
    ]

    while True:
        try:
            response = requests.post(
                url, 
                json={"queries": queries}
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", delay))
                time.sleep(retry_after)

                continue
            response.raise_for_status()

            break
        except requests.RequestException as e:
            print(f"{e}. Retrying in {delay} seconds...")
            time.sleep(delay)

    return response.json()["results"]


def query_nvd(batch):
    delay = 30
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = [("cveId", cve_id) for cve_id in batch]

    while True:
        try:
            response = requests.get(
                url, 
                params=params, 
                timeout=10
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", delay))
                time.sleep(retry_after)

                continue
            response.raise_for_status()

            break
        except requests.RequestException as e:
            print(f"Request failed: {e}. Retrying in {delay} seconds...")
            time.sleep(delay)

    return response.json()["vulnerabilities"]


def get_hf_token():
    token = os.getenv("HF_TOKEN")

    return token


def query_hf(api_token, prompt, findings):
    url = "https://router.huggingface.co/featherless-ai/v1/completions"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    full_prompt = f"{prompt}\n\n{findings}"

    json = {
        "model": "meta-llama/Meta-Llama-3.1-8B-Instruct",
        "prompt": full_prompt,
        "max_new_tokens": 600,
        "stream": False,
    }

    try:
        response = requests.post(
            url, 
            headers=headers, 
            json=json
        )

        if response.status_code == 402:
            raise RuntimeError("Your Huggingface Inference Providers credits are expired! It is not possible to generate a written report, you can still check all findings with findings command")
    except Exception:
        raise

    completion = response.json()

    texts = [choice['text'] for choice in completion['choices']]
    text = "\n".join(texts)

    return text
