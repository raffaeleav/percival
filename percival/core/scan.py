import os
import json

from percival.core import parse as prs, extract as ext
from percival.helpers import api, shell as sh, folders as fld


def trivy(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    vulns_file = fld.get_file_path(image_temp_dir, "trivy_vulns.json")
    pkgs_vulns_file = fld.get_file_path(image_temp_dir, "trivy_pkgs_vulns.json")
    lngs_vulns_file = fld.get_file_path(image_temp_dir, "trivy_lngs_vulns.json")

    cmd = f"trivy image --format json --output {vulns_file} {image_tag}"
    output = sh.run_command(cmd)

    pkgs_report, lngs_report = prs.parse_trivy_file(vulns_file)

    with open(pkgs_vulns_file, "w") as f:
        json.dump(pkgs_report, f, indent=2)
    with open(lngs_vulns_file, "w") as f:
        json.dump(lngs_report, f, indent=2)

    os.remove(vulns_file)

    return output


def update_trivy():
    cmd = "trivy image --download-db-only"
    output = sh.run_command(cmd)

    return output


def scan_os_packages(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    pkgs_vulns_file = fld.get_file_path(image_temp_dir, "pkgs_vulns.json")

    report = []
    pkg_files = ext.get_pkg_files(image_tag)

    for pkg_file in pkg_files:
        try:
            pkgs = prs.parse_pkg_file(pkg_file)
        except ValueError:
            continue

        results = api.query_osv(pkgs)

        for pkg, result in zip(pkgs, results):
            vulns = result.get("vulns", [])
            file_report = {
                "package": pkg["name"],
                "version": pkg["version"],
                "cves": [],
            }

            for vuln in vulns:
                cve = {
                    "id": vuln.get("id"),
                    "cvss": {"2.0": None, "3.0": None, "3.1": None},
                }

                file_report["cves"].append(cve)

            if file_report["cves"]:
                report.append(file_report)

    with open(pkgs_vulns_file, "w") as f:
        json.dump(report, f, indent=2)

    return report


def scan_javascript_package_json(lng_file):
    dependencies = prs.parse_javascript_package_json(lng_file)
    results = api.query_osv(dependencies)

    return results


def scan_python_requirements_txt(lng_file):
    dependencies = prs.parse_python_requirements_txt(lng_file)

    results = api.query_osv(dependencies)

    return results


def scan_java_pom_xml(lng_file):
    dependencies = prs.parse_java_pom_xml(lng_file)
    results = api.query_osv(dependencies)

    return results


lng_handlers = {
    ("javascript", "package.json"): scan_javascript_package_json,
    ("python", "requirements.txt"): scan_python_requirements_txt,
    ("java", "pom.xml"): scan_java_pom_xml,
}


def get_lng_vulns(language, file_type, lng_file):
    handler = lng_handlers.get((language, file_type))
    if handler:
        return handler(lng_file)
    else:
        return None


def scan_language_dependencies(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    lngs_vulns_file = fld.get_file_path(image_temp_dir, "lngs_vulns.json")

    report = []
    lng_files = ext.get_lng_files(image_tag)

    for lng_file in lng_files:
        lng = prs.parse_lng_file(lng_file)

        if lng is None:
            continue

        file_report = {
            "language": lng["language"],
            "file_type": lng["file_type"],
            "dependencies": [],
        }

        results = get_lng_vulns(lng["language"], lng["file_type"], lng_file)

        for result in results:
            dependency = {
                "dependency": result.get("package"),
                "version": result.get("version"),
                "cves": [],
            }

            vulns = result.get("vulns", [])

            for vuln in vulns:
                cve = {
                    "id": vuln.get("id"),
                    "cvss": {"2.0": None, "3.0": None, "3.1": None},
                }

                dependency["cves"].append(cve)

            if dependency["dependency"]:
                file_report["dependencies"].append(dependency)

        if file_report["dependencies"]:
            report.append(file_report)

    with open(lngs_vulns_file, "w") as f:
        json.dump(report, f, indent=2)

    return report
