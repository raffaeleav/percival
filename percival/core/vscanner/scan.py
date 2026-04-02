import os
import json

from percival.core.vscanner import pkgs_catalogers, lngs_catalogers
from percival.core.vscanner import parse as prs, query as qry
from percival.helpers import folders as fld, runtime as rnt, shell as sh


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


def syft(image_tag, type, catalogers):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while  extracting packages, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    vscanner_config_dir = fld.get_dir(fld.get_config_dir(), "vscanner")
    template_file = fld.get_file_path(vscanner_config_dir, "custom.template")
    output_file = fld.get_file_path(image_temp_dir, f"{type}.json")

    cmd = f"syft {image_tag} --override-default-catalogers {catalogers} --scope all-layers -o template -t {template_file} > {output_file}"
    output = sh.run_command(cmd)

    return output


def scan_os_packages(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while scanning with perCIVAl, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    pkgs_file = fld.get_file_path(image_temp_dir, "pkgs.json")
    pkgs_vulns_file = fld.get_file_path(image_temp_dir, "pkgs_vulns.json")

    report = []

    syft(image_tag, "pkgs", pkgs_catalogers)

    with open(pkgs_file, "r") as f:
        pkgs = json.load(f)

    for pkg in pkgs:
        purl = pkg["purl"]
        
        cves = qry.search_by_purl(purl)
            
        if cves:
            report.append({
                "name": pkg["name"],
                "version": pkg["version"],
                "layer": pkg["layer"],
                "type": pkg["type"],
                "cves": cves
            })
    
    with open(pkgs_vulns_file, "w") as f:
        json.dump(report, f, indent=2)

    return report


def scan_language_dependencies(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while scanning with perCIVAl, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    lngs_file = fld.get_file_path(image_temp_dir, "lngs.json")
    lngs_vulns_file = fld.get_file_path(image_temp_dir, "lngs_vulns.json")

    report = []
    
    syft(image_tag, "lngs", lngs_catalogers)

    with open(lngs_file, "r") as f:
        lngs = json.load(f)

    for lng in lngs:
        purl = lng["purl"]
        
        cves = qry.search_by_purl(purl)
            
        if cves:
            report.append({
                "name": lng["name"],
                "version": lng["version"],
                "layer": lng["layer"],
                "type": lng["type"],
                "cves": cves
            })
    
    with open(lngs_vulns_file, "w") as f:
        json.dump(report, f, indent=2)

    return report
