CVE_PATTERN = r"(CVE-\d{4}-\d{4,})"

vscanner_files = {"trivy_pkgs_vulns.json", "trivy_lngs_vulns.json", "pkgs_vulns.json", "lngs_vulns.json"}

cchecker_files = {"dive_report.json", "ccheck.json"}

sdetector_files = {"secrets.json"}

prompts = {
    "executive_summary": (
        "I will provide three LaTeX sections that contain an overview about security issues of a Docker container image, provide "
        "a concise general overview summarizing them. This overview is for the management staff, so it must be non technical." 
        "The response must be in plain text, suitable for direct use in a LaTeX section. Focus on key patterns, trends, "
        "and important observations rather than repeating individual table entries."
    ),
    "vulnerability_report": (
        "Read the findings provided in the following Markdown table (Only the 'Vulnerability Scanner' section) and write "
        "a concise general overview summarizing them. " 
        "The response must be in plain text, suitable for direct use in a LaTeX section. Focus on key patterns, trends, "
        "and important observations rather than repeating individual table entries."
    ),
    "configuration_report": (
        "Read the findings provided in the following Markdown table (Only the 'Configuration Checker' section) and write "
        "a concise general overview summarizing them. " 
        "The response must be in plain text, suitable for direct use in a LaTeX section. Focus on key patterns, trends, "
        "and important observations rather than repeating individual table entries."
    ),
    "secrets_report": (
        "Read the findings provided in the following Markdown table (Only the 'Secret Detection' section) and write "
        "a concise general overview summarizing them. " 
        "The response must be in plain text, suitable for direct use in a LaTeX section. Focus on key patterns, trends, "
        "and important observations rather than repeating individual table entries."
    ),
    "remediation_report": (
        "I will provide three LaTeX sections that contain an overview about security issues of a Docker container image, summarize "
        "the recommended actions to address them. "
        "The response must be in plain text, suitable for direct use in a LaTeX section. "
        "Focus on common remediation themes, priority areas, and general guidance rather than listing every individua recommendation."
    ),
}