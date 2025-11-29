import os
import base64


def format_pkgs_report(report):
    md_lines = (
        "| Package | Version | CVE ID | CVSS v2.0 | CVSS v3.0 | CVSS v3.1 |\n"
        "|-|-|-|-|-|-|\n"
    )

    for pkg in report:
        package = pkg.get("package", "")
        version = pkg.get("version", "")
        cves = pkg.get("cves", [])

        if not isinstance(cves, list):
            continue

        md_lines += f"| {package} | {version} |  |  |  |  |\n"

        for cve in cves:
            cve_id = cve.get("id", "")
            cvss = cve.get("cvss", {})

            v2 = cvss.get("2.0") or "N/A"
            v3 = cvss.get("3.0") or "N/A"
            v31 = cvss.get("3.1") or "N/A"

            md_lines += f"|  |  | {cve_id} | {v2} | {v3} | {v31} |\n"

        md_lines += "|---|---|---|---|---|---|\n"

    return md_lines


def format_lngs_report(report):
    md_lines = (
        "| Language | Filetype | Dependency | CVE ID | CVSS v2.0 | CVSS v3.0 | CVSS v3.1 |\n"
        "|-|-|-|-|-|-|-|\n"
    )

    for lng in report:
        language = lng.get("language", "")
        file = lng.get("file_type", "")
        dependencies = lng.get("dependencies", [])

        if not isinstance(dependencies, list):
            continue

        md_lines += f"| {language} | {file} |  |  |  |  |  |\n"

        for dependency in dependencies:
            name = dependency.get("name", "")
            cves = dependency.get("cves", [])

            md_lines += f"|  |  | {name} |  |  |  |  |\n"

            for cve in cves:
                cve_id = cve.get("id", "")
                cvss = cve.get("cvss", {})

                v2 = cvss.get("2.0", "N/A")
                v3 = cvss.get("3.0", "N/A")
                v31 = cvss.get("3.1", "N/A")

                md_lines += f"|  |  |  | {cve_id} | {v2} | {v3} | {v31} |\n"
                md_lines += "|---|---|---|---|---|---|---|\n"

        md_lines += "|---|---|---|---|---|---|---|\n"

    return md_lines


def format_dive_report(report):
    image = report.get("image", {})

    size = image.get("sizeBytes", "")
    bytes = image.get("inefficientBytes", "")
    score = image.get("efficiencyScore", "")

    md_lines = (
        "| Image size | Redundant bytes | Efficiency score |\n"
        "|-|-|-|\n"
    )

    md_lines += f"| {size} | {bytes} | {score} |\n"
    
    return md_lines


def format_ccheck_report(report):
    md_lines = (
        "| Dockerfile Condition | Description | Severity | Remediation |\n"
        "|-|-|-|-|\n"
    )

    for entry in report:
        condition = entry.get("condition", "")
        description = entry.get("description", "")
        severity = entry.get("severity", "")
        remediation = entry.get("remediation", "")

        md_lines += f"| {condition} | {description} | {severity} | {remediation} |\n"

    return md_lines


def sanitize(text):
    text = base64.b64encode(text.encode("utf-8", errors="ignore")).decode()

    return text


def wrap_column(column, max_len=35):
    column = "<br>".join([column[i:i+max_len] for i in range(0, len(column), max_len)])

    return column


def format_keys_report(report):
    md_lines = (
        "| File | Keys |\n"
        "|-|-|\n"
    )

    for entry in report:
        file_path = entry.get("file", "")   
        keys = entry.get("keys", [])

        if not keys:
            continue

        file_path = wrap_column(file_path)

        md_lines += f"| {file_path} |  |\n"

        for key in keys:
            key = sanitize(key)
            key = wrap_column(key)

            md_lines += f"| | {key} |\n"

    return md_lines


def format_strings_table(report):
    md_lines = (
        "| File | Secrets |\n"
        "|-|-|\n"
    )

    for entry in report:
        file_path = entry.get("file", "")   
        strings = entry.get("strings", [])

        if not strings:
            continue

        file_path = wrap_column(file_path)

        md_lines += f"| {file_path} |  |\n"

        for string in strings:
            string = sanitize(string)
            string = wrap_column(string)

            md_lines += f"| | {string} |\n"

    return md_lines
