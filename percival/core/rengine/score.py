from percival.helpers import api


def get_pkgs_cvss_scores(report):
    cve_map = {} 
    cve_ids = []

    batch_size = 50

    for entry in report:
        for cve in entry["cves"]:
            cve_ids.append(cve["id"])
            cve_map[cve["id"]] = cve

    # report is being modified in place
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

            if result_id in cve_map:
                cve_map[result_id]["cvss"] = cvss

    return report


def get_lngs_cvss_scores(report):
    cve_map = {}  # CVE ID -> CVE dict
    cve_ids = []

    # Build map and collect CVE IDs
    for entry in report:
        for dependency in entry["dependencies"]:
            for cve in dependency["cves"]:
                cve_ids.append(cve["id"])
                cve_map[cve["id"]] = cve

    batch_size = 50

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i+batch_size]
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

            if result_id in cve_map:
                cve_map[result_id]["cvss"] = cvss

    return report
