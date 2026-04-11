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
        "smells": ""
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
                tables["dive"] = tbt.convert_dive_findings(findings)
            elif "ccheck" in file: 
                tables["smells"] = tbt.convert_cchecker_findings(findings)

    no_results = "No configuration errors found\n"

    lines = [
        "## Configuration Checker Findings",
        "<details><summary>Image Efficiency (click to open)</summary>\n\n" +
        (tables["dive"] or no_results) +
        "\n</details>",

        "<details><summary>Configuration Errors (click to open)</summary>\n\n" +
        (tables["smells"] or no_results) +
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
        "smells": []
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
                image = findings.get("image", {})

                cchecker_findings["dive"] = {
                    "size": image.get("sizeBytes", ""),
                    "bytes": image.get("inefficientBytes", ""), 
                    "score": image.get("efficiencyScore", "")
                }
            elif "ccheck" in file: 
                for entry in findings: 
                    cchecker_findings["smells"].append({
                    "line": entry.get("line", ""),
                    "condition": entry.get("condition", ""),
                    "description": entry.get("description", ""), 
                    "severity": entry.get("severity", ""),
                    "remediation": entry.get("remediation", "")
                })

    return cchecker_findings


def get_sdetector_findings_json(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in sdetector_files
    ]

    sdetector_findings = {
        "keys": [],
        "strings": []
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

            for entry in findings: 
                file = entry.get("file", "")

                sdetector_findings["keys"].append({
                    "file": file,
                    "keys": entry.get("keys", []),
                })

                sdetector_findings["strings"].append({
                    "file": entry.get("file", ""),
                    "strings": entry.get("strings", [])
                })

    return sdetector_findings


def get_vscanner_findings_sarif(image_tag, findings_sarif):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in vscanner_files
    ]

    added_rules = set()

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

        if findings:
            for entry in findings:
                name = entry.get("name", "")
                version = entry.get("version", "")
                layer = entry.get("layer", "")

                for cve in entry.get("cves", []):
                    cve_id = cve.get("id", "")
                    severity = cve.get("severity", "")

                    if cve_id not in added_rules:
                        findings_sarif.add_rule(
                            name=cve_id,
                            ruleId=cve_id,
                            shortDescription=None,
                            fullDescription=None,
                            messageStrings=None
                        )

                        added_rules.add(cve_id)

                    # sarif severity mapping
                    severity = "error" if severity in ["CRITICAL", "HIGH"] else "note"
                    
                    findings_sarif.add_result(
                        ruleId=cve_id,
                        level=severity,
                        message_id=None,
                        arguments=[],
                        locations=[{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": layer
                                }
                            }
                        }],
                        properties={
                            "package_name": name,
                            "versione": version
                        }
                    )

    return findings_sarif


def get_cchecker_findings_sarif(image_tag, findings_sarif):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    dockerfile = fld.get_file_path(image_temp_dir, "Dockerfile")

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in cchecker_files
    ]

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

        if findings: 
            if "dive" in file:
                image = findings.get("image", {})
                score = image.get("efficiencyScore", "")

                findings_sarif.add_result(
                        ruleId="PCVL-CC-DIV",
                        level=None,
                        message_id=None,
                        arguments=[],
                        locations=[{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": dockerfile
                                }
                            }
                        }],
                        properties={
                            "score": score
                        }
                    )
            elif "ccheck" in file: 
                for entry in findings:
                    line = entry.get("line", "")
                    condition = entry.get("condition", "")
                    severity = entry.get("severity", "")

                    severity = "error" if severity in ["CRITICAL", "HIGH"] else "note"

                    findings_sarif.add_result(
                        ruleId="PCVL-CC-SML",
                        level=severity,
                        message_id=None,
                        arguments=[],
                        locations=[{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": dockerfile
                                }
                            }
                        }],
                        properties={
                            "line": line, 
                            "condition": condition
                        }
                    )

    return findings_sarif


def get_sdetector_findings_sarif(image_tag, findings_sarif):
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

            for entry in findings: 
                file_path = entry.get("file", "")
                keys = entry.get("keys", [])
                strings = entry.get("strings", [])

                if keys:
                    findings_sarif.add_result(
                        ruleId="PCVL-SD-KEY",
                        level=None,
                        message_id=None,
                        arguments=[],
                        locations=[{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": file_path
                                }
                            }
                        }],
                        properties={
                            "keys": keys
                        }
                    )
                
                if strings:
                    findings_sarif.add_result(
                        ruleId="PCVL-SD-STR",
                        level=None,
                        message_id=None,
                        arguments=[],
                        locations=[{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": file_path
                                }
                            }
                        }],
                        properties={
                            "strings": strings
                        }
                    )

    return findings_sarif
