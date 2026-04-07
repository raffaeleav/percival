CVE_PATTERN = r"(CVE-\d{4}-\d{4,})"

vscanner_files = {"trivy_pkgs_vulns.json", "trivy_lngs_vulns.json", "pkgs_vulns.json", "lngs_vulns.json"}

cchecker_files = {"dive_report.json", "ccheck.json"}

sdetector_files = {"secrets.json"}

prompts = {
    "executive_summary": (
        "I will provide three sections that contain an overview about security issues of a Docker container image, provide "
        "a concise general overview summarizing them. This overview is for the management staff, so it must be non technical." 
        "Write the paragraph in natural language." 
        "Focus on key patterns, trends, and important observations rather than repeating individual table entries."
    ),
    "intermediate_report": (
        "I'm conducting a Container Image Vulnerability Assessment on a Docker container image with the perCIVAl tool (that also leverages Trivy)."
        "Read the provided findings and write an overview in natural language." 
        "Focus on key patterns, trends, and important observations rather than repeating individual table entries."
    ),
    "remediation_report": (
        "I will provide three sections that contain an overview about security issues of a Docker container image, summarize "
        "the recommended actions to address them. "
        "Write the paragraph in natural language." 
        "Focus on common remediation themes, priority areas, and general guidance rather than listing every individual recommendation."
    ),
}