import os
import json

def parse_trivy_file(trivy_file):
    if not isinstance(trivy_file, (str, bytes, os.PathLike)):
        raise TypeError(f"trivy_file must be a path-like object, got {type(trivy_file).__name__} instead")
    
    with open(trivy_file, "r") as f:
        data = json.load(f)

    pkgs_report = []
    lngs_report = []

    for result in data.get("Results", []):
        type = result.get("Class", "unknown")

        for vuln in result.get("Vulnerabilities", []):
            entry = {
                "name": vuln.get("PkgName"),
                "version": vuln.get("InstalledVersion"),
                "layer": None,
                "type": None,
                "cves": [],
            }

            cve_entry = {
                "id": vuln.get("VulnerabilityID"),
                "severity": None,
                "cvss_base_score": None,
                "cvss_vector": None,
            }

            entry["cves"].append(cve_entry)

            if type == "os-pkgs":
                pkgs_report.append(entry)
            elif type == "lang-pkgs":
                lngs_report.append(entry)

    return pkgs_report, lngs_report