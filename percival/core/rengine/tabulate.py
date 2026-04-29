import base64


def convert_vscanner_findings(findings):
    md_lines = (
        "| Package | Version | Layer | Type | CVE ID | Severity | Base Score | Vector String |\n"
        "|-|-|-|-|-|-|-|-|\n"
    )

    for entry in findings:
        name = entry.get("name", "")
        version = entry.get("version", "")
        layer = entry.get("layer", "")
        type = entry.get("type", "")
        cves = entry.get("cves", [])

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


def convert_dive_findings(findings):
    image = findings.get("image", {})

    size = image.get("sizeBytes", "")
    bytes = image.get("inefficientBytes", "")
    score = image.get("efficiencyScore", "")

    md_lines = (
        "| Image size | Redundant bytes | Efficiency score |\n"
        "|-|-|-|\n"
    )

    md_lines += f"| {size} | {bytes} | {score} |\n"
    
    return md_lines


def convert_cchecker_findings(findings):
    md_lines = (
        "| Line | Dockerfile Condition | Description | Severity | Remediation |\n"
        "|-|-|-|-|-|\n"
    )

    for entry in findings:
        # each line has a \n that ruins table formatting
        line = entry.get("line", "").strip() 
        condition = entry.get("condition", "").strip()
        description = entry.get("description", "").strip()
        severity = entry.get("severity", "").strip()
        remediation = entry.get("remediation", "").strip()

        md_lines += f"| {line} | {condition} | {description} | {severity} | {remediation} |\n"
        
    return md_lines


def sanitize(text):
    if not isinstance(text, str):
        text = str(text)

    text = base64.b64encode(text.encode("utf-8", errors="ignore")).decode()

    return text


def wrap_column(column, max_len=60):
    column = "<br>".join([column[i:i+max_len] for i in range(0, len(column), max_len)])

    return column


def convert_keys_findings(findings):
    md_lines = (
        "| File | Keys | Pattern |\n"
        "|-|-|-|\n"
    )

    empty = True

    for entry in findings:
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


def convert_strings_findings(findings):
    md_lines = (
        "| File | High-Entropy Strings |\n"
        "|-|-|\n"
    )
    
    empty = True

    for entry in findings:
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
