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


def set_hf_token(token):
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    token_file = fld.get_file_path(rengine_config_dir, "token.txt")

    with open(token_file, "w") as f:
        f.write(token.strip())


def get_hf_token():
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    token_file = fld.get_file_path(rengine_config_dir, "token.txt")

    with open(token_file, "r") as f:
        token = f.read().strip()

    return token


def query_hf(api_token, prompt, findings):
    url = "https://api.huggingface-apis.com/v1/chat/completions"

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    full_prompt = f"{prompt}\n\n{findings}"

    response = requests.post(url, headers=headers, json={
        "model": "meta-llama/Llama-2-7b-chat-hf",
        "messages": [
            {
                "role": "system",
                "content": "You are a helpful assistant that summarizes vulnerability findings from Markdown tables in plain text suitable for LaTeX."
            },
            {
                "role": "user",
                "content": f"{full_prompt}"
            }
        ],
    })
    
    return response.json()["choices"][0]["message"]["content"]
