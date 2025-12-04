import re

from percival.core.rengine import prompts
from percival.helpers import api, folders as fld


def _get_prompt(section):
    if not isinstance(section, str):
        return None

    prompt = prompts.get(section)

    return prompt


def _extract_md_section(table, heading):
    if not isinstance(table, str) or not isinstance(heading, str):
        return None
    
    lines = table.splitlines()

    heading_text = heading.strip().lstrip("#").strip()
    pattern = re.compile(r"^(##+)\s+" + re.escape(heading_text) + r"\s*$", re.IGNORECASE)

    start_idx = None
    start_level = None

    for i, line in enumerate(lines):
        m = pattern.match(line)
        if m:
            start_idx = i + 1
            start_level = len(m.group(1))
            break

    if start_idx is None:
        return None

    collected = []

    for line in lines[start_idx:]:
        m = re.match(r"^(##+)\s+", line)
        if m and len(m.group(1)) <= start_level:
            break
        collected.append(line)

    while collected and collected[-1].strip() == "":
        collected.pop()

    section_table = "\n".join(collected)

    return section_table


def get_index():
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    index_file = fld.get_file_path(rengine_config_dir, "index.tex")

    with open(index_file, "r", encoding="utf-8") as f:
        text = f.read()

    return text


def get_title_page():
    lines = [
        r"\maketitle",
        r"\tableofcontents",
        r"\newpage",
    ]

    text = "\n\n".join(lines)

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


def get_vulnerability_report(image_tag, api_token):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "findings.md")    

    prompt = _get_prompt("vulnerability_report")

    if not prompt:
        return None

    with open(md_file, "r", encoding="utf-8") as f:
        findings = f.read()

    section_table = _extract_md_section(findings, "Vulnerability Scanner Findings")

    try:
        section = api.query_hf(api_token, prompt, section_table)
    except Exception as e:
        section = None

    no_results = "An error occurred with the text generation API while generating this section. Please retry generating the report."

    lines = [
        r"\section{Vulnerability Report}", 
        section or no_results,
    ]

    text = "\n\n".join(lines)

    return text


def get_configuration_report(image_tag, api_token):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "findings.md")    

    prompt = _get_prompt("configuration_report")

    if not prompt:
        return None

    with open(md_file, "r", encoding="utf-8") as f:
        findings = f.read()

    section_table = _extract_md_section(findings, "Configuration Checker Findings")

    try:
        section = api.query_hf(api_token, prompt, section_table)
    except Exception as e:
        section = None

    no_results = "An error occurred with the text generation API while generating this section. Please retry generating the report."

    lines = [
        r"\section{Configuration Report}", 
        section or no_results,
    ]

    text = "\n\n".join(lines)

    return text


def get_secrets_report(image_tag, api_token):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "findings.md")    

    prompt = _get_prompt("secrets_report")

    if not prompt:
        return None

    with open(md_file, "r", encoding="utf-8") as f:
        findings = f.read()

    section_table = _extract_md_section(findings, "Secret Detector Findings")

    try:
        section = api.query_hf(api_token, prompt, section_table)
    except Exception as e:
        section = None

    no_results = "An error occurred with the text generation API while generating this section. Please retry generating the report."

    lines = [
        r"\section{Secrets Report}", 
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
            "Package and language findings include CVSS scores (when available) for CVEs "
            "associated with each package or dependency installed in the container image, "
            "together with results derived from the Trivy scanner. "
            "Configuration findings highlight bad practices in Dockerfiles and include an "
            "efficiency assessment performed using the Dive tool. "
            "Secret detection findings report high-entropy strings and potential API keys. "
            "You can use the fview command to quickly open and inspect the file in your web browser."
        )
    ]

    text = "\n\n".join(lines)

    return text
