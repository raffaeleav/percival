import os
import json

from percival.core.vscanner import pkgs_dict, lngs_dict
from percival.core.vscanner import handle as hnd, parse as prs
from percival.helpers import api, folders as fld, runtime as rnt, shell as sh


def update_trivy():
    cmd = "trivy image --download-db-only"
    output = sh.run_command(cmd)

    return output


def trivy(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while scanning with Trivy, please fetch the image and try again")
    
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


def syft(image_tag, template, catalogers):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while  extracting packages, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    vscanner_config_dir = fld.get_dir(fld.get_config_dir(), "vscanner")
    template_file = fld.get_file_path(vscanner_config_dir, f"{template}.template")
    pkgs_file = fld.get_file_path(image_temp_dir, "pkgs.json")

    cmd = f"syft {image_tag} --override-default-catalogers {catalogers} --scope all-layers -o template -t {template_file} > {pkgs_file}"
    output = sh.run_command(cmd)

    return output


def scan_os_packages(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while scanning with perCIVAl, please fetch the image and try again")
    
    pkgs_catalogers = "os"
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    pkgs_file = fld.get_file_path(image_temp_dir, "pkgs.json")
    pkgs_vulns_file = fld.get_file_path(image_temp_dir, "pkgs_vulns.json")

    report = []

    syft(image_tag, "pkgs", pkgs_catalogers)
    # results = api.query_osv(pkgs)

    """
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
    """


def get_lng_files(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while extracting language files, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    layers_dir = fld.get_dir(image_temp_dir, "blobs")
    layers_dir = fld.get_dir(layers_dir, "sha256")

    lng_files = []
    norm_lngs_dict = [
        os.path.normpath(p).lstrip(os.sep)
        for v in lngs_dict.values()
        for p in (v if isinstance(v, list) else [v])
    ]

    for layer_dir in os.listdir(layers_dir):
        layer_path = os.path.join(layers_dir, layer_dir)
        files = fld.list_files(layer_path)

        for file in files:
            file_path = fld.get_file_path(layer_path, file)

            if os.path.islink(file_path):
                continue

            norm_file = os.path.normpath(file)

            if any(lng_file in norm_file for lng_file in norm_lngs_dict):
                lng_files.append(os.path.join(layers_dir, layer_dir, file))

    return lng_files


def scan_language_dependencies(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while scanning with perCIVAl, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    lngs_vulns_file = fld.get_file_path(image_temp_dir, "lngs_vulns.json")

    report = []
    lng_files = get_lng_files(image_tag)

    for lng_file in lng_files:
        lng = prs.parse_lng_file(lng_file)

        if lng is None:
            continue

        file_report = {
            "language": lng["language"],
            "file_type": lng["file_type"],
            "dependencies": [],
        }

        results = hnd.get_lng_vulns(lng["language"], lng["file_type"], lng_file)

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
