import time
import requests


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


def query_openai(prompt, json_files):
    url = ""

    payload = {
        "prompt": prompt,
        "files": json_files or {}
    }

    try:
        response = requests.post(
            url,
            json=payload,
        )

        response.raise_for_status()

    except requests.RequestException as e:
        return {"error": str(e)}
    
    return response.json()
