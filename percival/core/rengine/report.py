import os
import json
import platform

from percival.helpers import shell as sh, folders as fld
from percival.core.rengine import format as fmt, score as scr, filter as flt


def get_vscanner_report(image_tag):
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

    vscanner_report = "\n".join(lines)

    return vscanner_report


def get_cchecker_report(image_tag):
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
        "## Configuration Checker Findings",
        "<details><summary>Image Efficiency (click to open)</summary>\n\n" +
        (tables["dive"] or no_results) +
        "\n</details>",

        "<details><summary>Configuration Errors (click to open)</summary>\n\n" +
        (tables["dockerfile"] or no_results) +
        "\n</details>"
    ]

    cchecker_report = "\n".join(lines)

    return cchecker_report


def get_sdetector_report(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [file for file in files if file.endswith(".json")]

    keys_table = ""
    strings_table = ""

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

    no_results = "No API keys found\n"

    lines = [
        "## Secret Detector Findings",
        "<details><summary>API Keys (click to open)</summary>\n\n" +
        (keys_table or no_results) +
        "\n</details>",

        "<details><summary>High-Entropy Strings (click to open)</summary>\n\n" +
        (strings_table or no_results) +
        "\n</details>"
    ]

    sdetector_report = "\n".join(lines)

    return sdetector_report


def get_all_findings_report(image_tag):
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    styles_file = fld.get_file_path(rengine_config_dir, "styles.css")

    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "findings.md")
    html_file = fld.get_file_path(image_report_dir, "findings.html")

    vscanner_report = get_vscanner_report(image_tag)
    cchecker_report = get_cchecker_report(image_tag)
    sdetector_report = get_sdetector_report(image_tag)

    lines = [
        "# perCIVAl Findings",
        vscanner_report, 
        cchecker_report, 
        sdetector_report,
    ]

    report = "\n".join(lines)

    with open(md_file, "w") as f:
        f.write(report)

    cmd = (
        f"pandoc {md_file} "
        f"-o {html_file} "
        f"-c {styles_file} "
        "--self-contained "
    )

    output = sh.run_command(cmd)

    return output


def view_all_findings_report(image_tag):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    html_file = fld.get_file_path(image_report_dir, "findings.html")

    os_name = platform.system()

    if os_name == "Linux":
        cmd = f"xdg-open {html_file}"
    elif os_name == "Darwin":
        cmd = f"open {html_file}"

    output = sh.run_command(cmd)

    return output


def get_detailed_summary():
    lines = [
        "# Detailed Summary",
        "All the findings are organized in the findings.html file. "
        "This document provides a structured overview of all identified issues, and relevant "
        "metadata gathered during the analysis. "
        "Package and Language findings include CVSS scores (when available) of the CVEs related to each package / language "
        "depency installed in the container image. These findings also include an analysis performed using the "
        "Trivy tool."
        "Configuration findings highlight bad practices in Dockerfiles and include an efficiency check conducted with the "
        "Dive tool. "
        "Secret detection findings report high-entropy strings and plausible API keys. "
        "You can use the fview command to quickly open and inspect the file in your web browser. "
    ]

    text = "\n".join(lines)

    return text


def get_detailed_summary():
    lines = [
        "\\section{Detailed Summary}",
        (
            "All the findings are organized in the findings.html file. "
            "This document provides a structured overview of all identified issues and the "
            "metadata collected during the analysis. "
            "Package and language findings include CVSS scores (when available) for CVEs "
            "associated with each package or dependency installed in the container image, "
            "together with results derived from the Trivy scanner. "
            "Configuration findings highlight bad practices in Dockerfiles and include an "
            "efficiency assessment performed using the Dive tool. "
            "Secret detection findings report high-entropy strings and potential API keys. "
            "You can use the fview command to quickly open and inspect the file in your web browser."
        )
    ]

    text = "".join(lines)

    return text


def report(image_tag):
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    index_file = fld.get_file_path(rengine_config_dir, "index.tex")

    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    tex_file = fld.get_file_path(image_report_dir, "report.tex")
    pdf_file = fld.get_file_path(image_report_dir, "report.pdf")

    # exe_summary = get_executive_summary(image_tag)
    # vul_report = get_vulnerability_report(image_tag)
    # rem_report = get_remediation_report(image_tag)
    # fin_summary = get_findings_summary(image_tag)
    det_summary = get_detailed_summary()

    lines = [
        # exe_summary, 
        # vul_report,
        # rem_report,
        # fin_summary,
        det_summary,
    ]

    report = "\n".join(lines)

    with open(tex_file, "w") as f:
        f.write(report)

    cmd = (
        f"pandoc {tex_file} "
        f"-o {pdf_file} "
        f" --include-in-header={index_file}"
    )

    output = sh.run_command(cmd)

    return output
