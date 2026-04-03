import os
import json

from collections import defaultdict


def _group_trivy_pkgs_findings(report):
    if not isinstance(report, list):
        raise TypeError("Report should be a list")
    
    if not report: 
        return []

    grouped = defaultdict(lambda: {"package": None, "version": None, "cves": []})

    for entry in report:
        key = (entry["package"], entry["version"])

        grouped_entry = grouped[key]
        grouped_entry["package"] = entry["package"]
        grouped_entry["version"] = entry["version"]
        grouped_entry["cves"].extend(entry["cves"])

    return list(grouped.values())


def _group_trivy_lngs_findings(report):
    if not isinstance(report, list):
        raise TypeError("Report should be a list")
    
    result = []

    if not report: 
        return result

    item = {"language": "?", "file_type": "?", "dependencies": []}

    grouped = defaultdict(lambda: {"dependency": None, "version": None, "cves": []})

    for entry in report: 
        key = (entry["package"], entry["version"])

        grouped_entry = grouped[key]
        grouped_entry["dependency"] = entry["package"]
        grouped_entry["version"] = entry["version"]
        grouped_entry["cves"].extend(entry["cves"])

    item["dependencies"] = list(grouped.values())

    result.append(item)
    
    return result

    
def parse_trivy_file(trivy_file):
    if not isinstance(trivy_file, (str, bytes, os.PathLike)):
        raise TypeError(f"trivy_file must be a path-like object, got {type(trivy_file).__name__} instead")
    
    with open(trivy_file, "r") as f:
        data = json.load(f)

    pkgs_report = []
    lngs_report = []

    for result in data.get("Results", []):
        pkg_type = result.get("Class", "unknown")

        for vuln in result.get("Vulnerabilities", []):
            entry = {
                "package": vuln.get("PkgName"),
                "version": vuln.get("InstalledVersion"),
                "cves": [],
            }

            cve_entry = {
                "id": vuln.get("VulnerabilityID"),
                "cvss": {"2.0": None, "3.0": None, "3.1": None},
            }

            entry["cves"].append(cve_entry)

            if pkg_type == "os-pkgs":
                pkgs_report.append(entry)
            elif pkg_type == "lang-pkgs":
                lngs_report.append(entry)

    pkgs_report = _group_trivy_pkgs_findings(pkgs_report)
    lngs_report = _group_trivy_lngs_findings(lngs_report)

    return pkgs_report, lngs_report