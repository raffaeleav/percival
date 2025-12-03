
from percival.helpers import api, folders as fld
from percival.core.rengine import prompts

def get_prompt(section):
    prompt = prompts.get(section)

    return prompt


def get_vulnerability_report(image_tag, api_token):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    findings = fld.get_file_path(image_report_dir, "findings.md")    

    prompt = None

    section = api.query_hf(api_token, prompt, findings)

    lines = [
        "\\section{Vulnerability Report}", 
        section
    ]

    text = "\n\n".join(lines)

    return text


def get_detailed_summary():
    lines = [
        "\\section{Detailed Summary}",
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
