import os
import json

from percival.core.vscanner import parse as prs, query as qry
from percival.core.vscanner import pkgs_catalogers, lngs_catalogers
from percival.helpers import folders as fld, runtime as rnt, shell as sh


def update_trivy():
    cmd = "trivy image --download-db-only"
    output = sh.run_command(cmd)

    return output


def trivy(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while scanning with Trivy, please fetch the image and try again")
    
    local_tag = fld.sanitize(image_tag)
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), local_tag)
    vulns_file = fld.get_file_path(image_temp_dir, "trivy_vulns.json")
    pkgs_vulns_file = fld.get_file_path(image_temp_dir, "trivy_pkgs_vulns.json")
    lngs_vulns_file = fld.get_file_path(image_temp_dir, "trivy_lngs_vulns.json")

    cmd = f"trivy image --format json --output {vulns_file} {image_tag}"
    output = sh.run_command(cmd)

    pkgs_findings, lngs_findings = prs.parse_trivy_file(vulns_file)

    with open(pkgs_vulns_file, "w") as f:
        json.dump(pkgs_findings, f, indent=2)
    with open(lngs_vulns_file, "w") as f:
        json.dump(lngs_findings, f, indent=2)

    os.remove(vulns_file)

    return output


def syft(image_tag, type, catalogers):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while  extracting packages, please fetch the image and try again")
    
    local_tag = fld.sanitize(image_tag)
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), local_tag)
    vscanner_config_dir = fld.get_dir(fld.get_config_dir(), "vscanner")
    template_file = fld.get_file_path(vscanner_config_dir, "custom.template")
    output_file = fld.get_file_path(image_temp_dir, f"{type}.json")

    cmd = f"syft {image_tag} --override-default-catalogers {catalogers} --scope all-layers -o template -t {template_file} > {output_file}"
    output = sh.run_command(cmd)

    return output


def scan(image_tag, item_type):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while scanning with perCIVAl, please fetch the image and try again")
    
    local_tag = fld.sanitize(image_tag)
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), local_tag)
    items_file = fld.get_file_path(image_temp_dir, f"{item_type}.json")
    items_vulns_file = fld.get_file_path(image_temp_dir, f"{item_type}_vulns.json")

    findings = []

    catalogers = pkgs_catalogers if item_type == "pkgs" else lngs_catalogers

    syft(image_tag, item_type, catalogers)

    with open(items_file, "r") as f:
        items = json.load(f)

    for item in items:
        purl = item["purl"]
        
        cves = qry.search_by_purl(purl)
            
        if cves:
            findings.append({
                "name": item["name"],
                "version": item["version"],
                "layer": item["layer"],
                "type": item["type"],
                "cves": cves
            })
    
    with open(items_vulns_file, "w") as f:
        json.dump(findings, f, indent=2)

    return findings
