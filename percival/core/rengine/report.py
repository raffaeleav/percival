import os
import json
import platform

from percival.helpers import shell as sh, folders as fld
from percival.core.rengine import format as fmt, score as scr, filter as flt


def report_vscanner(image_tag):
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

    vreport = "\n".join(lines)

    return vreport


def report_cchecker(image_tag):
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
        "<details><summary>Image Efficiency (click to open)</summary>\n\n" +
        (tables["dive"] or no_results) +
        "\n</details>",

        "<details><summary>Configuration Errors (click to open)</summary>\n\n" +
        (tables["dockerfile"] or no_results) +
        "\n</details>"
    ]

    creport = "\n".join(lines)

    return creport


def report_sdetector(image_tag):
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
        "## Secret Detection Report",
        "<details><summary>API Keys (click to open)</summary>\n\n" +
        (keys_table or no_results) +
        "\n</details>",

        "<details><summary>High-Entropy Strings (click to open)</summary>\n\n" +
        (strings_table or no_results) +
        "\n</details>"
    ]

    sreport = "\n".join(lines)

    return sreport


def report_all(image_tag):
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    styles_file = fld.get_file_path(rengine_config_dir, "styles.css")

    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "report.md")
    html_file = fld.get_file_path(image_report_dir, "report.html")

    vreport = report_vscanner(image_tag)
    creport = report_cchecker(image_tag)
    sreport = report_sdetector(image_tag)

    lines = [
        "# perCIVAl Report",
        vreport, 
        creport, 
        sreport,
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


def view_report(image_tag):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    html_file = fld.get_file_path(image_report_dir, "report.html")

    os_name = platform.system()

    if os_name == "Linux":
        cmd = f"xdg-open {html_file}"
    elif os_name == "Darwin":
        cmd = f"open {html_file}"

    output = sh.run_command(cmd)

    return output
