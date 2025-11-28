import os
import re
import json

from percival.helpers import shell as sh, folders as fld
from percival.core.rengine import format as fmt, score as scr, filter as flt

def vscan_report(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [file for file in files if file.endswith(".json")]

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
                report = json.loads(content)
            except json.JSONDecodeError:
                report = None

        if report:
            if "pkgs" in file:
                report = flt.filter_pkgs_report(report)
                report = scr.get_pkgs_cvss_scores(report)

                table = fmt.format_pkgs_report(report)

                if "trivy" in file:
                    tables["trivy_pkgs"] = table
                else:
                    tables["percival_pkgs"] = table
                
            elif "lngs" in file:
                report = flt.filter_lngs_report(report)
                report = scr.get_lngs_cvss_scores(report)

                table = fmt.format_lngs_report(report)

                if "trivy" in file:
                    tables["trivy_lngs"] = table
                else:
                    tables["percival_lngs"] = table

    no_results = "No vulnerabilities found\n"

    lines = [
        "## Vulnerability Report",
        "### Trivy OS packages findings",
        tables["trivy_pkgs"] or no_results,
        "### Trivy language dependencies findings",
        tables["trivy_lngs"] or no_results,
        "### PerCIVAl OS packages findings",
        tables["percival_pkgs"] or no_results,
        "### PerCIVAl language dependencies findings",
        tables["percival_lngs"] or no_results
    ]

    vreport = "\n".join(lines)

    return vreport


def ccheck_report(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [file for file in files if file.endswith(".json")]

    tables = {
        "dive": "",
        "dockerfile": ""
    }

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                report = json.loads(content)
            except json.JSONDecodeError:
                report = None

        if report: 
            if "dive" in file:
                table = fmt.format_dive_report(report)

                tables["dive"] = table
            elif "ccheck" in file: 
                table = fmt.format_ccheck_report(report)

                tables["dockerfile"] = table

    no_results = "No configuration errors found\n"

    lines = [
        "## Configuration Report",
        "### Image Efficiency",
        tables["dive"] or no_results,
        "### Configuration Errors",
        tables["dockerfile"] or no_results,
    ]

    creport = "\n".join(lines)

    return creport


def sdetector_report(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [file for file in files if file.endswith(".json")]

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                report = json.loads(content)
            except json.JSONDecodeError:
                report = None

        if report: 
            if "secrets" in file:
                keys_table = fmt.format_keys_report(report)
                strings_table = fmt.format_strings_table(report)

                break

    no_results = "No secrets found\n"

    lines = [
        "## Secret Detection Report",
        "### API Keys",
        keys_table or no_results,
        "### High-Entropy Strings",
        strings_table or no_results,
    ]

    sreport = "\n".join(lines)

    return sreport


def report(image_tag):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "report.md")
    pdf_file = fld.get_file_path(image_report_dir, "report.pdf")

    vreport = vscan_report(image_tag)
    creport = ccheck_report(image_tag)
    sreport = sdetector_report(image_tag)

    lines = [
        "# perCIVAl Report",
        vreport, 
        creport, 
        sreport,
    ]

    report = "\n".join(lines)

    with open(md_file, "w") as f:
        f.write(report)

    sh.run_command(
        f"pandoc {md_file} -o {pdf_file} "
        "--pdf-engine=xelatex "
        "-V geometry:margin=1.5cm "
        "-V fontsize=12pt "
        "-V mainfont='Times New Roman' "
        "-V monofont='Courier New' "
        "-V colorlinks=true "  
        "-V linkcolor=blue "
        "-V urlcolor=cyan "
        "-V title='Vulnerability Assessment Report' "  
        "-V lang=en "
    )
