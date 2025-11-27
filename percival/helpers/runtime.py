import os

from yaspin import yaspin
from yaspin.spinners import Spinners
from percival.helpers import folders as fld, shell as sh


def is_docker_running():
    try:
        sh.run_command("docker ps")

        return True
    except RuntimeError:
        return False
    

def is_fetched(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    tar_file = fld.get_file_path(image_temp_dir, image_tag + ".tar")

    return os.path.exists(tar_file)
    

def run_with_spinner(desc, func, *args, **kwargs):
    with yaspin(Spinners.arc, text=desc) as spinner:
        try:
            result = func(*args, **kwargs)
            spinner.ok("[Success]")

            return result
        except Exception as e:
            spinner.fail("[Failure]")

            print(f"{e}")