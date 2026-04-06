CVE_PATTERN = r"(CVE-\d{4}-\d{4,})"

vscanner_files = {"trivy_pkgs_vulns.json", "trivy_lngs_vulns.json", "pkgs_vulns.json", "lngs_vulns.json"}

cchecker_files = {"dive_report.json", "ccheck.json"}

sdetector_files = {"secrets.json"}

prompts = {
    "executive_summary": (
        "I will provide three sections that contain an overview about security issues of a Docker container image, provide "
        "a concise general overview summarizing them. This overview is for the management staff, so it must be non technical." 
        "Focus on key patterns, trends, and important observations rather than repeating individual table entries."
    ),
    "vulnerability_report": (
        "Read the provided findings and write a concise and general overview summarizing them. " 
        "Focus on key patterns, trends, and important observations rather than repeating individual table entries."
    ),
    "configuration_report": (
        "Read the provided findings and write a concise and general overview summarizing them. " 
        "Focus on key patterns, trends, and important observations rather than repeating individual table entries."
    ),
    "secrets_report": (
        "Read the provided findings and write a concise and general overview summarizing them. " 
        "Focus on key patterns, trends, and important observations rather than repeating individual table entries."
    ),
    "remediation_report": (
        "I will provide three sections that contain an overview about security issues of a Docker container image, summarize "
        "the recommended actions to address them. "
        "Focus on common remediation themes, priority areas, and general guidance rather than listing every individual recommendation."
    ),
}