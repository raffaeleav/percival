import sys
import cmd2
import platform

from percival.vscanner import scan as scn
from percival.cchecker import check as chk
from percival.sdetector import detect as det
from percival.rengine import report as rpt
from percival.core import extract as ext, fetch as ftc
from percival.helpers import folders as fld, runtime as rnt


class Percival(cmd2.Cmd):
    intro = "Welcome to perCIVAl shell, type help to list commands or exit to quit"
    prompt = "perCIVAl > "

    def __init__(self):
        """
        Initialize the PerCIVAl shell, check the operating system,
        and perform initial setup.
        """
        super().__init__()
        self.params = {"image": None}
        fld.setup()

        os_name = platform.system()

        if os_name != "Linux" and os_name != "Darwin":
            print(f"{os_name} is currently not supported")
            sys.exit(0)

    def do_analyze(self, image_tag):
        """
        Analyze a Docker image with all the components.
        """
        if not rnt.is_fetched(image_tag):
            print("[Failure] To analyze an image, it should be fetched first")
            return

        rnt.run_with_spinner("Updating Trivy db", scn.update_trivy)
        rnt.run_with_spinner("Scanning for vulnerabilities with Trivy", scn.trivy, image_tag)
        rnt.run_with_spinner("Scanning for OS packages vulnerabilities", scn.scan_os_packages, image_tag)
        rnt.run_with_spinner("Scanning for language dependencies vulnerabilites", scn.scan_language_dependencies, image_tag)

        rnt.run_with_spinner("Reconstructing Dockerfile", chk.reconstruct_docker_file, image_tag)
        rnt.run_with_spinner("Running image efficiency check with dive", chk.dive, image_tag)
        rnt.run_with_spinner("Checking Dockerfile best practices", chk.check_config, image_tag)

        rnt.run_with_spinner("Finding secrets", det.detect_secrets, image_tag)

        rnt.run_with_spinner("Generating report", rpt.report, image_tag)

    def do_fetch(self, image_tag):
        """
        Pull a Docker image from the registry.

        Args:
            image_tag (str): The Docker image tag to pull.
        """
        if not rnt.is_docker_running():
            print("[Failure] To fetch an image, Docker daemon should be running")
            return

        rnt.run_with_spinner("Pulling image", ftc.pull, self, image_tag)
        rnt.run_with_spinner("Extracting manifest", ext.get_manifest, self, image_tag)
        rnt.run_with_spinner("Extracting layers", ext.get_layers, self, image_tag)
        
    def do_vscan(self, image_tag):
        """
        Check for OS packages and language dependency vulnerabilities in a Docker image.

        Args:
            image_tag (str): The Docker image tag to scan.
        """
        rnt.run_with_spinner("Updating Trivy db", scn.update_trivy)
        rnt.run_with_spinner("Scanning for vulnerabilities with Trivy", scn.trivy, image_tag)
        rnt.run_with_spinner("Scanning for OS packages vulnerabilities", scn.scan_os_packages, image_tag)
        rnt.run_with_spinner("Scanning for language dependencies vulnerabilites", scn.scan_language_dependencies, image_tag)

    def do_ccheck(self, image_tag):
        """
        Check for insecure practices in a Docker image.

        Args:
            image_tag (str): The Docker image tag to check.
        """
        rnt.run_with_spinner("Reconstructing Dockerfile", chk.reconstruct_docker_file, image_tag)
        rnt.run_with_spinner("Running image efficiency check with dive", chk.dive, image_tag)
        rnt.run_with_spinner("Checking Dockerfile best practices", chk.check_config, image_tag)

    
    def do_sdetect(self, image_tag):
        """
        Finds common secrets in a Docker image.

        Args:
            image_tag (str): The Docker image tag to analyze.
        """
        rnt.run_with_spinner("Finding secrets", det.detect_secrets, image_tag)


    def do_report(self, image_tag):
        """
        Generate a vulnerability report for a Docker image.

        Args:
            image_tag (str): The Docker image tag to generate the report for.
        """
        rnt.run_with_spinner("Generating report", rpt.report, image_tag)

    def do_cleanup(self, image_tag):
        """
        Remove temporary files created during fetching and scanning.

        Args:
            image_tag (str): The Docker image tag related to temporary files.
        """
        rnt.run_with_spinner("Deleting temp files", fld.remove_temp_files, image_tag)

    def do_clear(self, arg):
        """
        Clear the shell screen.
        """
        print("\033c", end="")

    def do_exit(self, arg):
        """
        Exit the PerCIVAl shell.

        Returns:
            bool: True to signal the shell to exit.
        """
        return True


if __name__ == "__main__":
    app = Percival()
    app.cmdloop()
