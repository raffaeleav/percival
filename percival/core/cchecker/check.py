import re
import json
import yaml

from percival.core.cchecker import dockerfile_commands, run_regex
from percival.helpers import folders as fld, runtime as rnt, shell as sh


def reconstruct_docker_file(image_tag): 
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while checking configuration, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    dockerfile = fld.get_file_path(image_temp_dir, "Dockerfile")

    cmd = f"docker history --no-trunc {image_tag} --format json"
    output = sh.run_command(cmd)

    layers = [json.loads(line) for line in output.strip().split("\n") if line]
    # reverse to get chronological order
    layers = list(reversed(layers))
    
    dockerfile_lines = []

    for layer in layers:
        created_by = layer.get("CreatedBy", "")
        
        # nop prefix case
        if "#(nop)" in created_by:
            line = created_by.split("#(nop)")[1].strip()
            dockerfile_lines.append(line)
            
        # fs changes case
        else:
            cleaned_line = re.sub(run_regex, '', created_by)
        
            if not cleaned_line.startswith(dockerfile_commands):
                line = f"RUN {cleaned_line}"
            else:
                line = cleaned_line
                
            dockerfile_lines.append(line)
    
    dockerfile_lines = "\n".join(dockerfile_lines)

    with open(dockerfile, "w") as f:
        f.write(dockerfile_lines)

    return dockerfile


def dive(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while executing Dive, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    dive_report = fld.get_file_path(image_temp_dir, "dive.json")

    cmd = f"dive {image_tag} --json {dive_report}"
    output = sh.run_command(cmd)

    return output


def check_config(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred while checking configuration, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    ccheck_file = fld.get_file_path(image_temp_dir, "ccheck.json")
    
    dockerfile = fld.get_file_path(image_temp_dir, "Dockerfile")
    cchecker_config_dir = fld.get_dir(fld.get_config_dir(), "cchecker")
    rules_file = fld.get_file_path(cchecker_config_dir, "rules.yaml")

    report = []

    with open(dockerfile, "r") as f:
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
