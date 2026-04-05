import base64


def format_report(report):
    md_lines = (
        "| Package | Version | Layer | Type | CVE ID | Severity | Base Score | Vector String |\n"
        "|-|-|-|-|-|-|-|-|\n"
    )

    for item in report:
        name = item.get("name", "")
        version = item.get("version", "")
        layer = item.get("layer", "")
        type = item.get("type", "")
        cves = item.get("cves", [])

        if not isinstance(cves, list):
            continue

        md_lines += f"| {name} | {version} | {layer} | {type} |  |  |  |  |\n"

        for cve in cves:
            id = cve.get("id", "")
            severity = cve.get("severity", "")
            base_score = cve.get("cvss_base_score", "")
            vector_string =  cve.get("cvss_vector", "")

            md_lines += f"|  |  |  |  | {id} | {severity} | {base_score} | {vector_string} |\n"

        md_lines += "|---|---|---|---|---|---|---|---|\n"

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
    if not isinstance(text, str):
        text = str(text)

    text = base64.b64encode(text.encode("utf-8", errors="ignore")).decode()

    return text


def wrap_column(column, max_len=60):
    column = "<br>".join([column[i:i+max_len] for i in range(0, len(column), max_len)])

    return column


def format_keys_report(report):
    md_lines = (
        "| File | Keys | Pattern |\n"
        "|-|-|-|\n"
    )

    empty = True

    for entry in report:
        file_path = entry.get("file", "")   
        keys = entry.get("keys", [])

        if not keys:
            continue

        empty = False

        file_path = wrap_column(file_path)

        md_lines += f"| {file_path} |  |\n"

        for key in keys:
            pattern = key["key_type"]

            value = sanitize(key["value"])
            value = wrap_column(value)

            md_lines += f"| | {value} | {pattern} |\n"

    if empty:
        md_lines = ""

    return md_lines


def format_strings_table(report):
    md_lines = (
        "| File | High-Entropy Strings |\n"
        "|-|-|\n"
    )
    
    empty = True

    for entry in report:
        file_path = entry.get("file", "")   
        strings = entry.get("strings", [])

        if not strings:
            continue

        empty = False

        file_path = wrap_column(file_path)

        md_lines += f"| {file_path} |  |\n"

        for string in strings:
            string = sanitize(string)
            string = wrap_column(string)

            md_lines += f"| | {string} |\n"

    if empty:
        md_lines = ""

    return md_lines
