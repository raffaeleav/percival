import json
import yaml

from percival.helpers import shell as sh
from percival.helpers import folders as fld


def reconstruct_docker_file(image_tag): 
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    docker_file = fld.get_file_path(image_temp_dir, "Dockerfile")

    cmd = f"docker history --no-trunc {image_tag} > {docker_file}"
    output = sh.run_command(cmd)

    return output


def dive(image_tag): 
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    dive_report = fld.get_file_path(image_temp_dir, "dive_report.json")

    cmd = f"dive {image_tag} --json {dive_report}"
    output = sh.run_command(cmd)

    return output


def check_config(image_tag):
    module_dir = fld.get_module_dir("cchecker")
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    ccheck_file = fld.get_file_path(image_temp_dir, "ccheck.json")
    

    docker_file = fld.get_file_path(image_temp_dir, "Dockerfile")
    rules_file = fld.get_file_path(module_dir, "rules.yaml")

    report = []

    with open(docker_file, "r") as f:
        lines = f.readlines()

    with open(rules_file, "r") as f:
        data = yaml.safe_load(f)
        rules = data["docker_file_rules"]

    for rule in rules:
        condition = rule["condition"]

        for line in lines:
            if condition in line:
                report.append(
                    rule["condition"],
                    rule["description"],
                    rule["severity"],
                    rule["remediation"]
                )

    with open(ccheck_file, "w") as f:
        json.dump(report, f, indent=2)

    return report
