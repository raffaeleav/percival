import re

from percival.core.rengine import CVE_PATTERN


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