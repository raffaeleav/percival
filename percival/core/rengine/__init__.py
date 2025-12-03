CVE_PATTERN = r"(CVE-\d{4}-\d{4,})"

prompts = {
    "executive_summary": (
        ""
    ),
    "vulnerability_report": (
        "Read the findings provided in the following Markdown table (Only the 'Vulnerability Scanner' section) and write "
        "a concise general overview summarizing them. " 
        "The response must be in plain text, suitable for direct use in a LaTeX section. Focus on key patterns, trends, "
        "and important observations rather than repeating individual table entries."
    ),
    "configuration_report": (
        ""
    ),
    "secrets_report": (
        ""
    ),
    "remediation_report": (
        ""
    ),
    "findings_summary": (
    ),
}