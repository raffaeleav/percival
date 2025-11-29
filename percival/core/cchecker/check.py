import json
import yaml

from percival.helpers import folders as fld, runtime as rnt, shell as sh


def reconstruct_docker_file(image_tag): 
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while checking configuration, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    docker_file = fld.get_file_path(image_temp_dir, "Dockerfile")

    cmd = f"docker history --no-trunc {image_tag} > {docker_file}"
    output = sh.run_command(cmd)

    return output


def dive(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while executing Dive, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    dive_report = fld.get_file_path(image_temp_dir, "dive_report.json")

    cmd = f"dive {image_tag} --json {dive_report}"
    output = sh.run_command(cmd)

    return output


def check_config(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while checking configuration, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    ccheck_file = fld.get_file_path(image_temp_dir, "ccheck.json")
    
    docker_file = fld.get_file_path(image_temp_dir, "Dockerfile")
    cchecker_config_dir = fld.get_dir(fld.get_config_dir(), "cchecker")
    rules_file = fld.get_file_path(cchecker_config_dir, "rules.yaml")

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
