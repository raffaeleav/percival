import os
import json
import shutil
import platform

from datetime import date
from jinja2 import Template
from dicttoxml import dicttoxml
from simple_sarif import Sarif
from percival.helpers import api, folders as fld, shell as sh
from percival.core.rengine import format as fmt, write as wrt


def get_findings_html(image_tag, output_file):
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    styles_file = fld.get_file_path(rengine_config_dir, "styles.css")

    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    md_file = fld.get_file_path(image_report_dir, "findings.md")

    if not output_file:
        output_file = fld.get_file_path(image_report_dir, "findings.html")

    vscanner_findings = fmt.get_vscanner_findings_html(image_tag)
    cchecker_findings = fmt.get_cchecker_findings_html(image_tag)
    sdetector_findings = fmt.get_sdetector_findings_html(image_tag)

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
        f"-o {output_file} "
        f"-c {styles_file} "
        "--self-contained "
    )

    output = sh.run_command(cmd)

    return output


def view_findings_html(image_tag, output_file):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)

    if not output_file:
        output_file = fld.get_file_path(image_report_dir, "findings.html")

    os_name = platform.system()

    if os_name == "Linux":
        cmd = f"xdg-open {output_file}"
    elif os_name == "Darwin":
        cmd = f"open {output_file}"

    output = sh.run_command(cmd)

    return output


def get_findings_json(image_tag, output_file):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)

    if not output_file:
        output_file = fld.get_file_path(image_report_dir, "findings.json")

    vscanner_findings = fmt.get_vscanner_findings_json(image_tag)
    cchecker_findings = fmt.get_cchecker_findings_json(image_tag)
    sdetector_findings = fmt.get_sdetector_findings_json(image_tag)

    timestamp = date.today()

    findings_json = {
        "metadata": {
        "tool_name": "perCIVAl",
        "image_tag": f"{image_tag}",
        "timestamp": f"{timestamp}",
        },
        "findings": {
            "vscanner": vscanner_findings, 
            "cchecker": cchecker_findings,
            "sdetector": sdetector_findings
        }
    }

    with open(output_file, "w") as f:
        json.dump(findings_json, f, indent=2)

    return findings_json


def get_findings_xml(image_tag, output_file):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    findings_json_file = fld.get_file_path(image_report_dir, "findings.json")

    if not output_file:
        output_file = fld.get_file_path(image_report_dir, "findings.xml")

    if os.path.isfile(findings_json_file): 
        with open(findings_json_file, "r") as f:
            findings_json = json.load(f)
    else:
        findings_json = get_findings_json(image_tag, None)

    findings_xml = dicttoxml(findings_json, custom_root='percival_findings', attr_type=False).decode("utf-8")

    with open(output_file, "w") as f:
        f.write(findings_xml)

    return findings_xml


def get_findings_sarif(image_tag, output_file):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)

    if not output_file:
        output_file = fld.get_file_path(image_report_dir, "findings.sarif")

    findings_sarif = Sarif(file=output_file, recreate=True)

    # custom rules for smells and secrets
    findings_sarif.add_rule("Dive efficiency analysis", "PCVL-CC-DIV", None, None, None)
    findings_sarif.add_rule("Dockerfile smells", "PCVL-CC-SML", None, None, None)

    findings_sarif.add_rule("Secrets", "PCVL-SD-KEY", None, None, None)
    findings_sarif.add_rule("High entropy strings", "PCVL-SD-STR", None, None, None)

    fmt.get_vscanner_findings_sarif(image_tag, findings_sarif)
    fmt.get_cchecker_findings_sarif(image_tag, findings_sarif)
    fmt.get_sdetector_findings_sarif(image_tag, findings_sarif)

    findings_sarif.save()

    return findings_sarif


def get_findings_custom(image_tag, template, output_file):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    findings_json_file = fld.get_file_path(image_report_dir, "findings.json")
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    default_template_file = fld.get_file_path(rengine_config_dir, "default.template")

    if not output_file:
        output_file = fld.get_file_path(image_report_dir, "findings_custom.md")

    if not template:
        with open(default_template_file, "r") as f:
            template = f.read()
    else:
        with open(template, "r") as f:
            template = f.read()

    template = Template(template)

    if os.path.isfile(findings_json_file): 
        with open(findings_json_file, "r") as f:
            findings_json = json.load(f)
    else:
        findings_json = get_findings_json(image_tag, None)

    findings_custom = template.render(result=findings_json)

    with open(output_file, "w") as f:
        f.write(findings_custom)

    return findings_custom


def get_findings(image_tag, format, output_file, **kwargs): 
    mode = {
            "html": get_findings_html,
            "json": get_findings_json,
            "xml": get_findings_xml,
            "sarif": get_findings_sarif, 
            "custom": get_findings_custom
        }

    target = mode.get(format)

    if format == "custom":
        return target(image_tag, kwargs.get("template"), output_file)

    return target(image_tag, output_file)


def report(image_tag):
    image_report_dir = fld.get_dir(fld.get_reports_dir(), image_tag)
    findings_json_file = fld.get_file_path(image_report_dir, "findings.json")
    tex_file = fld.get_file_path(image_report_dir, "report.tex")
    
    rengine_config_dir = fld.get_dir(fld.get_config_dir(), "rengine")
    titlepage_file = fld.get_file_path(rengine_config_dir, "titlepage.tex")

    # needed to avoid openout_any = p
    shutil.copy(titlepage_file, image_report_dir)
    
    api_token = api.get_token()

    if not api_token: 
        raise RuntimeError("No HuggingFace API token found, please set your token with 'export HF_TOKEN=<your_token>'")
    
    if os.path.isfile(findings_json_file): 
        with open(findings_json_file, "r") as f:
            findings_json = json.load(f)
    else:
        findings_json = get_findings_json(image_tag, None)

    index = wrt.get_index()
    
    vul_report = wrt.get_intermediate_report(findings_json, "vscanner", api_token)
    con_report = wrt.get_intermediate_report(findings_json, "cchecker", api_token)
    sec_report = wrt.get_intermediate_report(findings_json, "sdetector", api_token)

    sections = [ vul_report, con_report, sec_report ]

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
