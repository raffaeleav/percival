from percival.core.rengine import prompts
from percival.helpers import api, folders as fld


def get_prompt(section):
    prompt = prompts.get(section)

    return prompt


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


def get_vulnerability_report(image_tag, api_token):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "findings.md")    

    prompt = get_prompt("vulnerability_report")

    with open(md_file, "r", encoding="utf-8") as f:
        findings = f.read()

    try:
        section = api.query_hf(api_token, prompt, findings)
    except Exception:
        section = None

    no_results = "An error occurred with the text generation API while generating this section. Please retry generating the report."

    lines = [
        r"\section{Vulnerability Report}", 
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
