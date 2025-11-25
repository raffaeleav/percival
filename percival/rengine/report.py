import os
import re
import json
import base64

from percival.helpers import api, shell as sh, folders as fld

CVE_PATTERN = r"(CVE-\d{4}-\d{4,})"


def is_cve(cve_id):
    if "CVE-" in cve_id:
        return True
    else:
        return False
    

def extract_cve_id(cve_id):
    match = re.search(CVE_PATTERN, cve_id)
    
    if match:
        return match.group(1)


def filter_pkgs_cve_ids(report): 
    for entry in report:
        entry["cves"] = [
            cve for cve in entry["cves"] 
            if cve.get("id") and is_cve(cve["id"])
        ]

    return report 


def extract_pkgs_cve_ids(report):
    for entry in report:
        for cve in entry["cves"]:
                cve_id = cve.get("id")
                cve_id = extract_cve_id(cve_id)
                
                if cve_id:
                    cve["id"] = cve_id
                
    return report


def filter_pkgs_report(report):
    report = filter_pkgs_cve_ids(report)
    report = extract_pkgs_cve_ids(report)
    
    return report


def get_pkgs_cvss_scores(report):
    cve_ids = []
    batch_size = 50

    for entry in report:
        for cve in entry["cves"]:
            cve_ids.append(cve["id"])

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i: i+batch_size]

        results = api.query_nvd(batch)

        for result in results:
            result_id = result["cve"]["id"]
            metrics = result["cve"].get("metrics", {})

            cvss = {"2.0": None, "3.0": None, "3.1": None}

            if "cvssMetricV2" in metrics:
                cvss["2.0"] = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            if "cvssMetricV30" in metrics:
                cvss["3.0"] = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            if "cvssMetricV31" in metrics:
                cvss["3.1"] = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

            for entry in report:
                for cve in entry["cves"]:
                    if cve["id"] == result_id:
                        cve["cvss"] = cvss

    return report


def filter_lngs_report_cve_ids(report): 
    for entry in report:
        for dependency in entry["dependencies"]: 
            dependency["cves"] = [
                cve 
                for cve in dependency["cves"] 
                if cve.get("id") and is_cve(cve["id"])
            ]

    return report


def filter_lngs_report(report):
    report = filter_lngs_report_cve_ids(report)
    
    return report


def get_lngs_cvss_scores(report):
    cve_ids = []
    batch_size = 50

    for entry in report:
        for dependecy in entry["dependencies"]:
            for cve in dependecy["cves"]:
                cve_ids.append(cve["id"])

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i: i+batch_size]

        results = api.query_nvd(batch)

        for result in results:
            result_id = result["cve"]["id"]
            metrics = result["cve"].get("metrics", {})

            cvss = {"2.0": None, "3.0": None, "3.1": None}

            if "cvssMetricV2" in metrics:
                cvss["2.0"] = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            if "cvssMetricV30" in metrics:
                cvss["3.0"] = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            if "cvssMetricV31" in metrics:
                cvss["3.1"] = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

            for entry in report:
                for dependecy in entry["dependencies"]:
                    for cve in dependecy["cves"]:
                        if cve["id"] == result_id:
                            cve["cvss"] = cvss

    return report


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


def vscan_report(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [file for file in files if file.endswith(".json")]

    tables = {
        "trivy_pkgs": "",
        "trivy_lngs": "",
        "percival_pkgs": "",
        "percival_lngs": ""
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                report = json.loads(content)
            except json.JSONDecodeError:
                report = None

        if report:
            if "pkgs" in file:
                report = filter_pkgs_report(report)
                report = get_pkgs_cvss_scores(report)

                table = format_pkgs_report(report)

                if "trivy" in file:
                    tables["trivy_pkgs"] = table
                else:
                    tables["percival_pkgs"] = table
                
            elif "lngs" in file:
                report = filter_lngs_report(report)
                report = get_lngs_cvss_scores(report)

                table = format_lngs_report(report)

                if "trivy" in file:
                    tables["trivy_lngs"] = table
                else:
                    tables["percival_lngs"] = table

    no_results = "No vulnerabilities found\n"

    lines = [
        "## Vulnerability Report",
        "### Trivy OS packages findings",
        tables["trivy_pkgs"] or no_results,
        "### Trivy language dependencies findings",
        tables["trivy_lngs"] or no_results,
        "### PerCIVAl OS packages findings",
        tables["percival_pkgs"] or no_results,
        "### PerCIVAl language dependencies findings",
        tables["percival_lngs"] or no_results
    ]

    vreport = "\n".join(lines)

    return vreport


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


def ccheck_report(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [file for file in files if file.endswith(".json")]

    tables = {
        "dive": "",
        "dockerfile": ""
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                report = json.loads(content)
            except json.JSONDecodeError:
                report = None

        if report: 
            if "dive" in file:
                table = format_dive_report(report)

                tables["dive"] = table
            elif "ccheck" in file: 
                table = format_ccheck_report(report)

                tables["dockerfile"] = table

    no_results = "No configuration errors found\n"

    lines = [
        "## Configuration Report",
        "### Image Efficiency",
        tables["dive"] or no_results,
        "### Configuration Errors",
        tables["dockerfile"] or no_results,
    ]

    creport = "\n".join(lines)

    return creport


def sanitize(text):
    return base64.b64encode(text.encode("utf-8", errors="ignore")).decode()


def format_keys_report(report):
    md_lines = (
        "| File | Keys |\n"
        "|-|-|\n"
    )

    for entry in report:
        file = entry.get("file", "")   
        keys = entry.get("keys", [])

        md_lines += f"| {file} |  |\n"

        for key in keys:
            key = sanitize(key)
            md_lines += f"| | {key} |\n"

    return md_lines


def format_strings_table(report):
    md_lines = (
        "| File | Secrets |\n"
        "|-|-|\n"
    )

    for entry in report:
        file = entry.get("file", "")   
        strings = entry.get("strings", [])

        md_lines += f"| {file} |  |\n"

        for string in strings:
            string = sanitize(string)
            md_lines += f"| | {string} |\n"

    return md_lines


def sdetector_report(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [file for file in files if file.endswith(".json")]

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                report = json.loads(content)
            except json.JSONDecodeError:
                report = None

        if report: 
            if "secrets" in file:
                keys_table = format_keys_report(report)
                strings_table = format_strings_table(report)

                break

    no_results = "No secrets found\n"

    lines = [
        "## Secret Detection Report",
        "### API Keys",
        keys_table or no_results,
        "### High-Entropy Strings",
        strings_table or no_results,
    ]

    sreport = "\n".join(lines)

    return sreport


def report(image_tag):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "report.md")
    pdf_file = fld.get_file_path(image_report_dir, "report.pdf")

    vreport = vscan_report(image_tag)
    creport = ccheck_report(image_tag)
    sreport = sdetector_report(image_tag)

    lines = [
        "# perCIVAl Report",
        vreport, 
        creport, 
        sreport,
    ]

    report = "\n".join(lines)

    with open(md_file, "w") as f:
        f.write(report)

    sh.run_command(
        f"pandoc {md_file} -o {pdf_file} "
        "--pdf-engine=xelatex "
        "-V geometry:margin=1.5cm "
        "-V fontsize=12pt "
        "-V mainfont='Times New Roman' "
        "-V monofont='Courier New' "
        "-V colorlinks=true "  
        "-V linkcolor=blue "
        "-V urlcolor=cyan "
        "-V title='Vulnerability Assessment Report' "  
        "-V lang=en "
    )
