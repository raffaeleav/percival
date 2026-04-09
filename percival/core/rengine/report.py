import os
import json
import shutil
import platform

from percival.helpers import api, folders as fld, shell as sh
from percival.core.rengine import write as wrt
from percival.core.rengine import vscanner_files, cchecker_files, sdetector_files
from percival.core.rengine import tabulate as tbt


def _get_vscanner_findings(image_tag):
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


def _get_cchecker_findings(image_tag):
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


def _get_sdetector_findings(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    files = fld.list_files(image_temp_dir)
    files = [
        file for file in files
        if os.path.basename(file) in sdetector_files
    ]

    keys_table = ""
    strings_table = ""

    for file in files:
        with open(os.path.join(image_temp_dir, file), "r") as f:
            content = f.read()

            try:
                findings = json.loads(content)
            except json.JSONDecodeError:
                findings = None

        if findings: 
            keys_table = tbt.convert_keys_findings(findings)
            strings_table = tbt.convert_strings_findings(findings)

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

    sdetector_findings = "\n".join(lines)

    return sdetector_findings


def get_findings(image_tag):
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    styles_file = fld.get_file_path(rengine_config_dir, "styles.css")

    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "findings.md")
    html_file = fld.get_file_path(image_report_dir, "findings.html")

    vscanner_findings = _get_vscanner_findings(image_tag)
    cchecker_findings = _get_cchecker_findings(image_tag)
    sdetector_findings = _get_sdetector_findings(image_tag)

    lines = [
        "# perCIVAl Findings",
        vscanner_findings, 
        cchecker_findings, 
        sdetector_findings,
    ]

    findings = "\n".join(lines)

    with open(md_file, "w") as f:
        f.write(findings)

    cmd = (
        f"pandoc {md_file} "
        f"-o {html_file} "
        f"-c {styles_file} "
        "--self-contained "
    )

    output = sh.run_command(cmd)

    return output


def view_findings(image_tag):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    html_file = fld.get_file_path(image_report_dir, "findings.html")

    os_name = platform.system()

    if os_name == "Linux":
        cmd = f"xdg-open {html_file}"
    elif os_name == "Darwin":
        cmd = f"open {html_file}"

    output = sh.run_command(cmd)

    return output


def report(image_tag):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    tex_file = fld.get_file_path(image_report_dir, "report.tex")\
    
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    titlepage_file = fld.get_file_path(rengine_config_dir, "titlepage.tex")

    # needed to avoid openout_any = p
    shutil.copy(titlepage_file, image_report_dir)
    
    api_token = api.get_token()

    if not api_token: 
        raise RuntimeError("No HuggingFace API token found, please set your token with 'export HF_TOKEN=<your_token>'")

    index = wrt.get_index()
    
    vul_report = wrt.get_vulnerability_report(image_tag, api_token)
    con_report = wrt.get_configuration_report(image_tag, api_token)
    sec_report = wrt.get_secrets_report(image_tag, api_token)

    sections = [vul_report, con_report, sec_report]

    exe_summary = wrt.get_executive_summary(sections, api_token)
    rem_report = wrt.get_remediation_report(sections, api_token)
    det_summary = wrt.get_detailed_summary()

    lines = [
        index,
        r"\graphicspath{{./}{" + rengine_config_dir + "/}} ",
        r"\begin{document}",
        r"\include{titlepage}",
        r"\tableofcontents",
        r"\pagebreak",
        exe_summary, 
        r"\pagebreak",
        vul_report,
        r"\pagebreak",
        con_report,
        r"\pagebreak",
        sec_report,
        r"\pagebreak",
        rem_report,
        r"\pagebreak",
        det_summary,
        r"\end{document}"
    ]

    report = "\n".join(lines)

    with open(tex_file, "w") as f:
        f.write(report)

    cmd = f"latexmk -pdf -interaction=nonstopmode -outdir={image_report_dir} {tex_file}"
    
    output = sh.run_command(cmd)

    return output
