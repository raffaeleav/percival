import re

from percival.core.rengine import CVE_PATTERN


def is_cve(cve_id):
    if not isinstance(cve_id, str):
        return False
    else: 
        result = "CVE-" in cve_id

        return result
    

def _extract_cve_id(cve_id):
    if not isinstance(cve_id, str):
        return None
    
    match = re.search(CVE_PATTERN, cve_id)
    
    if match:
        return match.group(1)
    else: 
        return None


def _filter_pkgs_cve_ids(report): 
    if not isinstance(report, list):
        return []

    for entry in report:
        entry["cves"] = [
            cve for cve in entry["cves"] 
            if cve.get("id") and is_cve(cve["id"])
        ]

    return report 


def _extract_pkgs_cve_ids(report):
    if not isinstance(report, list):
        return []
    
    for entry in report:
        for cve in entry["cves"]:
                cve_id = cve.get("id")
                cve_id = _extract_cve_id(cve_id)
                
                if cve_id:
                    cve["id"] = cve_id
                
    return report


def filter_pkgs_report(report):
    if not isinstance(report, list):
        return []
    
    report = _filter_pkgs_cve_ids(report)
    report = _extract_pkgs_cve_ids(report)
    
    return report


def _filter_lngs_report_cve_ids(report): 
    if not isinstance(report, list):
        return []
    
    for entry in report:
        for dependency in entry["dependencies"]: 
            dependency["cves"] = [
                cve 
                for cve in dependency["cves"] 
                if cve.get("id") and is_cve(cve["id"])
            ]

    return report


def filter_lngs_report(report):
    if not isinstance(report, list):
        return []
    
    report = _filter_lngs_report_cve_ids(report)
    
    return report