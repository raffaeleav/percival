import os
import re
import json
import xml.etree.ElementTree as et

from collections import defaultdict
from percival.core.dloader import lngs_dict


def _group_trivy_pkgs_findings(report):
    if not isinstance(report, list):
        raise TypeError("Report should be a list")

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


def parse_pkg_file(pkg_file):
    if not isinstance(pkg_file, (str, bytes, os.PathLike)):
        raise TypeError(f"pkg_file must be a path-like object, got {type(pkg_file).__name__} instead")
    
    if "dpkg" in pkg_file:
        return _parse_dpkg_pkgs(pkg_file)
    elif "pacman" in pkg_file:
        return _parse_pacman_pkgs(pkg_file)
    elif "rpm" in pkg_file:
        return _parse_rpm_pkgs(pkg_file)
    else:
        raise ValueError("Unknown package file type: expected 'dpkg', 'pacman', or 'rpm' in filename")


def _extract_blocks(pkg_file):
    if not isinstance(pkg_file, (str, bytes, os.PathLike)):
        raise TypeError(f"pkg_file must be a path-like object, got {type(pkg_file).__name__} instead")
    
    with open(pkg_file, "r") as f:
        contents = f.read()

    blocks = []

    if contents:
        blocks = contents.strip().split("\n\n")

    return blocks


def _parse_dpkg_pkgs(pkg_file):
    if not isinstance(pkg_file, (str, bytes, os.PathLike)):
        raise TypeError(f"pkg_file must be a path-like object, got {type(pkg_file).__name__} instead")
    
    pkgs = []
    blocks = _extract_blocks(pkg_file)

    for block in blocks:
        pkg = {"version": None, "name": None}

        lines = block.split("\n")

        for line in lines:
            if line.startswith("Package: "):
                pkg["name"] = line.split("Package: ")[1]

            if line.startswith("Version: "):
                pkg["version"] = line.split("Version: ")[1]
                break

        pkgs.append(pkg)

    return pkgs


def _parse_pacman_pkgs(pkg_file):
    raise ValueError("Not supported yet")


def _parse_rpm_pkgs(pkg_file):
    raise ValueError("Not supported yet")


def parse_lng_file(lng_file):
    if not isinstance(lng_file, (str, bytes, os.PathLike)):
        raise TypeError(f"lng_file must be a path-like object, got {type(lng_file).__name__} instead")
    
    lng = {
        "language": None,
        "file_type": None,
    }

    for key, values in lngs_dict.items():
        for value in values:
            if value in lng_file:
                lng["language"] = key
                lng["file_type"] = value

                return lng

    return None


def parse_javascript_package_json(lng_file):
    if not isinstance(lng_file, (str, bytes, os.PathLike)):
        raise TypeError(f"lng_file must be a path-like object, got {type(lng_file).__name__} instead")
    
    with open(lng_file, "r") as f:
        data = json.load(f)

    dependencies = []
    data = data.get("dependencies", {})

    for name, info in data.items():
        version = info.get("version", "unknown")
        dependency = {"name": name, "version": version}

        dependencies.append(dependency)

    return dependencies


def parse_python_requirements_txt(lng_file):
    if not isinstance(lng_file, (str, bytes, os.PathLike)):
        raise TypeError(f"lng_file must be a path-like object, got {type(lng_file).__name__} instead")
    
    dependencies = []

    with open(lng_file, "r") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            match = re.match(r"^([a-zA-Z0-9_\-]+)([=<>!~]+)?(.+)?$", line)
            if match:
                name = match.group(1)
                version = match.group(3) if match.group(3) else "unknown"

                dependency = {"name": name, "version": version}

                dependencies.append(dependency)

    return dependencies


def parse_java_pom_xml(lng_file):
    if not isinstance(lng_file, (str, bytes, os.PathLike)):
        raise TypeError(f"lng_file must be a path-like object, got {type(lng_file).__name__} instead")
    
    dependencies = []
    tree = et.parse(lng_file)
    root = tree.getroot()

    ns = {}
    if root.tag.startswith("{"):
        uri = root.tag.split("}")[0].strip("{")
        ns = {"mvn": uri}

    for dep in root.findall(".//mvn:dependencies/mvn:dependency", ns):
        artifact_id = dep.find("mvn:artifactId", ns)
        version = dep.find("mvn:version", ns)

        if artifact_id is not None and version is not None:
            dependency = {
                "name": artifact_id.text.strip(),
                "version": version.text.strip(),
            }

            dependencies.append(dependency)

    return dependencies
