import os
import json

from percival.helpers import folders as fld
from percival.core.rengine import tabulate as tbt
from percival.core.rengine import vscanner_files, cchecker_files, sdetector_files


def get_vscanner_findings_html(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in vscanner_files
    ]

    tables = {
        "trivy_pkgs": "",
        "trivy_lngs": "",
        "percival_pkgs": "",
        "percival_lngs": ""
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

        if findings:
            table = tbt.convert_vscanner_findings(findings)
            
            if "pkgs" in file:
                if "trivy" in file:
                    tables["trivy_pkgs"] = table
                else:
                    tables["percival_pkgs"] = table
                
            elif "lngs" in file:
                if "trivy" in file:
                    tables["trivy_lngs"] = table
                else:
                    tables["percival_lngs"] = table

    no_results = "No vulnerabilities found\n"

    lines = [
        "## Vulnerability Scanner Findings",
        "<details><summary>Trivy OS packages findings (click to open)</summary>\n\n" +
        (tables["trivy_pkgs"] or no_results) +
        "\n</details>",

        "<details><summary>Trivy language dependencies findings (click to open)</summary>\n\n" +
        (tables["trivy_lngs"] or no_results) +
        "\n</details>",

        "<details><summary>PerCIVAl OS packages findings (click to open)</summary>\n\n" +
        (tables["percival_pkgs"] or no_results) +
        "\n</details>",

        "<details><summary>PerCIVAl language dependencies findings (click to open)</summary>\n\n" +
        (tables["percival_lngs"] or no_results) +
        "\n</details>"
    ]

    vscanner_findings = "\n".join(lines)

    return vscanner_findings


def get_cchecker_findings_html(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in cchecker_files
    ]

    tables = {
        "dive": "",
        "dockerfile": ""
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

        if findings: 
            if "dive" in file:
                table = tbt.convert_dive_findings(findings)

                tables["dive"] = table
            elif "ccheck" in file: 
                table = tbt.convert_cchecker_findings(findings)

                tables["dockerfile"] = table

    no_results = "No configuration errors found\n"

    lines = [
        "## Configuration Checker Findings",
        "<details><summary>Image Efficiency (click to open)</summary>\n\n" +
        (tables["dive"] or no_results) +
        "\n</details>",

        "<details><summary>Configuration Errors (click to open)</summary>\n\n" +
        (tables["dockerfile"] or no_results) +
        "\n</details>"
    ]

    cchecker_findings = "\n".join(lines)

    return cchecker_findings


def get_sdetector_findings_html(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in sdetector_files
    ]

    tables = {
        "keys": "",
        "strings": ""
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

        if findings: 
            tables["keys"] = tbt.convert_keys_findings(findings)
            tables["strings"] = tbt.convert_strings_findings(findings)

    no_results = "No API keys found\n"

    lines = [
        "## Secret Detector Findings",
        "<details><summary>API Keys (click to open)</summary>\n\n" +
        (tables["keys"] or no_results) +
        "\n</details>",

        "<details><summary>High-Entropy Strings (click to open)</summary>\n\n" +
        (tables["strings"] or no_results) +
        "\n</details>"
    ]

    sdetector_findings = "\n".join(lines)

    return sdetector_findings


def get_vscanner_findings_json(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in vscanner_files
    ]

    vscanner_findings = {
        "trivy_pkgs": {},
        "trivy_lngs": {},
        "percival_pkgs": {},
        "percival_lngs": {}
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None
            
            if "pkgs" in file:
                if "trivy" in file:
                    vscanner_findings["trivy_pkgs"] = findings
                else:
                    vscanner_findings["percival_pkgs"] = findings
                
            elif "lngs" in file:
                if "trivy" in file:
                    vscanner_findings["trivy_lngs"] = findings
                else:
                    vscanner_findings["percival_lngs"] = findings

    return vscanner_findings


def get_cchecker_findings_json(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in cchecker_files
    ]

    cchecker_findings = {
        "dive": {},
        "dockerfile": {}
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

        if findings: 
            if "dive" in file:
                cchecker_findings["dive"] = findings
            elif "ccheck" in file: 
                cchecker_findings["dockerfile"] = findings

    return cchecker_findings


def get_sdetector_findings_json(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in sdetector_files
    ]

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

    sdetector_findings = findings

    return sdetector_findings


def get_vscanner_findings_sarif(image_tag, findings_sarif):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in vscanner_files
    ]

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

        if findings:
            for item in findings:
                name = item.get("name", "unknown")
                version = item.get("version", "unknown")
                layer = item.get("layer", "unknown")

                for cve in item.get("cves", []):
                    cve_id = cve.get("id", "CVE-UNKNOWN")
                    sev = cve.get("severity", "UNKNOWN")
                    
                    # sarif severity mapping
                    severity = "error" if sev in ["CRITICAL", "HIGH"] else "warning"
                    
                    findings_sarif.add_result(
                        rule_id=cve_id,
                        message=f"Vulnerability {cve_id} in {name} ({version}). CVSS: {cve.get('cvss_base_score')}",
                        file_path=f"File path: {layer}",
                        level=severity
                    )

    return findings_sarif