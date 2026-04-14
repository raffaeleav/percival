import re

from percival.core.rengine import prompts
from percival.helpers import api, folders as fld


def _get_prompt(section):
    if not isinstance(section, str):
        return None

    prompt = prompts.get(section)

    return prompt


def get_index():
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    index_file = fld.get_file_path(rengine_config_dir, "index.tex")

    with open(index_file, "r", encoding="utf-8") as f:
        text = f.read()

    return text


def get_intermediate_report(findings_json, section, api_token):
    max_tokens = 900
    prompt = _get_prompt("intermediate_report")

    if not prompt:
        return None

    findings_json = findings_json.get("findings", {}).get(f"{section}", {})

    try:
        section = api.query_hf(api_token, prompt, findings_json, max_tokens)
    except Exception as e:
        section = None

    no_results = "An error occurred with the text generation API while generating this section. Please retry generating the report."

    lines = [
        r"\section{Vulnerability Report}" if section == "vscanner" else None, 
        r"\section{Configuration Report}" if section == "cchecker" else None, 
        r"\section{Secrets Report}" if section == "sdetector" else None, 
        section or no_results,
    ]

    text = "\n\n".join(filter(None, lines))

    return text


def get_executive_summary(sections, api_token):
    prompt = _get_prompt("executive_summary")

    if not prompt:
        return None
    
    findings = "\n\n".join(sections)

    try:
        findings = "\n\n".join(sections)

        section = api.query_hf(api_token, prompt, findings)
    except Exception as e:
        section = None

    no_results = "An error occurred with the text generation API while generating this section. Please retry generating the report."

    lines = [
        r"\section{Executive Summary}", 
        section or no_results,
    ]

    text = "\n\n".join(lines)

    return text


def get_remediation_report(sections, api_token):
    prompt = _get_prompt("remediation_report")

    if not prompt:
        return None

    findings = "\n\n".join(sections)

    try:
        section = api.query_hf(api_token, prompt, findings)
    except Exception:
        section = None

    no_results = "An error occurred with the text generation API while generating this section. Please retry generating the report."

    lines = [
        r"\section{Remediation Report}", 
        section or no_results,
    ]

    text = "\n\n".join(lines)

    return text


def get_detailed_summary():
    lines = [
        r"\section{Detailed Summary}",
        (
            "All the findings are organized in the findings.html file. "
            "This document provides a structured overview of all identified issues and the "
            "metadata collected during the analysis. "
            "Package and language findings include CVSS scores for CVEs "
            "associated with each package or dependency installed in the container image, "
            "together with results derived from the Trivy scanner (if requested). "
            "Configuration findings highlight bad practices in Dockerfiles and include an "
            "efficiency assessment performed using the Dive tool. "
            "Secret detection findings report high-entropy strings and potential API keys. "
            "You can use the 'findings' command to quickly open and inspect the file in your web browser."
        )
    ]

    text = "\n\n".join(lines)

    return text
