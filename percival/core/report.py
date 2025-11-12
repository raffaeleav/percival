import os
import json

from percival.core import parse as prs
from percival.helpers import api, shell as sh, folders as fld


def get_pkgs_cvss_scores(report):
    cve_ids = []
    batch_size = 50

    for entry in report:
        for cve in entry["cves"]:
            if cve["id"] and prs.is_cve(cve["id"]):
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


def get_lngs_cvss_scores(report):
    cve_ids = []
    batch_size = 50

    for entry in report:
        for dependecy in entry["dependencies"]:
            for cve in dependecy["cves"]:
                if cve["id"] and prs.is_cve(cve["id"]):
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


def filter_pkgs(report):
    filtered = []

    for pkg in report:
        package = pkg.get("package", "")
        version = pkg.get("version", "")
        cves = pkg.get("cves", [])

        if not isinstance(cves, list):
            continue

        cves_with_scores = [
            cve
            for cve in cves
            if any(cve.get("cvss", {}).get(k) for k in ["2.0", "3.0", "3.1"])
        ]
        cves_without_scores = [cve for cve in cves if cve not in cves_with_scores]

        filtered_cves = cves_with_scores[:10]
        if len(filtered_cves) < 10:
            filtered_cves += cves_without_scores[: 10 - len(filtered_cves)]

        filtered.append(
            {
                "package": package,
                "version": version,
                "cves": filtered_cves,
            }
        )

    return filtered


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
                v3 = cvss.get("2.1", "N/A")
                v31 = cvss.get("3.1", "N/A")

                md_lines += f"|  |  |  | {cve_id} | {v2} | {v3} | {v31} |\n"
                md_lines += "|---|---|---|---|---|---|---|\n"

        md_lines += "|---|---|---|---|---|---|---|\n"

    return md_lines


def vscan_report(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "report.md")
    pdf_file = fld.get_file_path(image_report_dir, "report.pdf")

    files = fld.list_files(image_temp_dir)
    files = [file for file in files if file.endswith(".json")]

    tables = {
        "trivy_pkgs": "",
        "trivy_lngs": "",
        "percival_pkgs": "",
        "percival_lngs": "",
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
                report = get_pkgs_cvss_scores(report)
                report = filter_pkgs(report)
                table = format_pkgs_report(report)

                if "trivy" in file:
                    tables["trivy_pkgs"] = table
                else:
                    tables["percival_pkgs"] = table
                
            elif "lngs" in file:
                report = get_lngs_cvss_scores(report)
                table = format_lngs_report(report)

                if "trivy" in file:
                    tables["trivy_lngs"] = table
                else:
                    tables["percival_lngs"] = table

    no_results = "No vulnerabilities found\n"

    lines = [
        "# Vulnerability Report",
        "## Trivy OS packages findings",
        tables["trivy_pkgs"] or no_results,
        "## Trivy language dependencies findings",
        tables["trivy_lngs"] or no_results,
        "## PerCIVAl OS packages findings",
        tables["percival_pkgs"] or no_results,
        "## PerCIVAl language dependencies findings",
        tables["percival_lngs"] or no_results,
    ]

    vscan_report = "\n".join(lines)

    with open(md_file, "w") as f:
        f.write(vscan_report)

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


def report(image_tag):
    vscan_report(image_tag)
