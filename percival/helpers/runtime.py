import os
import sys
import platform

from yaspin import yaspin
from yaspin.spinners import Spinners
from percival.helpers import folders as fld, shell as sh


def check_support():
    os_name = platform.system()

    if os_name != "Linux" and os_name != "Darwin":
        print(f"{os_name} is currently not supported")

        sys.exit(0)


def is_docker_running():
    try:
        sh.run_command("docker ps")

        return True
    except RuntimeError:
        return False


def is_fetched(image_tag):
    images_dir = fld.get_images_dir()
    tar_file = fld.get_file_path(images_dir, image_tag + ".tar")

    return os.path.exists(tar_file)


def is_analyzed(image_tag):
    report_dir = fld.get_reports_dir()
    image_report_dir = fld.get_dir(report_dir, image_tag)
    findings_file = fld.get_file_path(image_report_dir, "findings.html")

    return os.path.exists(findings_file)
    

def run_with_spinner(desc, func, *args, **kwargs):
    with yaspin(Spinners.arc, text=desc) as spinner:
        try:
            result = func(*args, **kwargs)
            spinner.ok("\033[38;2;76;241;76m[Success]\033[0m")

            return result
        except Exception as e:
            spinner.fail("\033[38;2;241;76;76m[Failure]\033[0m")
            print(f"{e}")

            raise


def clear():
    print("\033c", end="")


def restart():
    python = sys.executable
    os.execl(python, python, *sys.argv)
    