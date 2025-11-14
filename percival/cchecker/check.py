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


def check_conig(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    docker_file = fld.get_file_path(image_temp_dir, "Dockerfile")

    # [to-do] ...