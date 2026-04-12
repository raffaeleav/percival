import cmd2
import argparse

from percival.core.prunner import run
from percival.core.vscanner import query as qry
from percival.core.rengine import report as rpt 
from percival.helpers import folders as fld, runtime as rnt
from percival.core.dloader import extract as ext, fetch as ftc 

class Percival(cmd2.Cmd):
    intro = "Welcome to perCIVAl shell, type \033[1mhelp\033[0m to list commands or \033[1mexit\033[0m to quit"
    prompt = "\033[38;2;0;122;204mperCIVAl >\033[0m "

    analyze_parser = argparse.ArgumentParser()
    analyze_parser.add_argument(
        "image_tag", 
        help="Docker image tag to analyze"
    )
    analyze_parser.add_argument(
            "--with-trivy",
            action="store_true",
            help="Run additional vulnerability scanning with Trivy"
    )
    analyze_parser.add_argument(
        "--format", 
        choices=["html", "json", "xml", "sarif", "custom"], 
        default="html", 
        help="Findings format (default: html)"
    )
    analyze_parser.add_argument(
        "--template",
        default=None,
        help="Custom Go template for findings formatting"
    )
    analyze_parser.add_argument(
        "--output",
        default=None,
        help="Output file path"
    )


    def __init__(self):
        """
        Initialize the perCIVAl shell, check the operating system,
        and perform initial setup.
        """
        super().__init__()

        rnt.clear()
        rnt.check_support()
        fld.setup()

        self.params = {
            "image": None,
        }


    def do_fetch(self, image_tag):
        """
        Pull a Docker image from the registry.
        """
        if not rnt.is_docker_running():
            print("\033[38;2;241;76;76m[Failure]\033[0m To fetch an image, Docker daemon should be running")
            
            return

        rnt.run_with_spinner("Pulling image", ftc.pull, self, image_tag)
        rnt.run_with_spinner("Extracting manifest", ext.get_manifest, self, image_tag)
        rnt.run_with_spinner("Extracting layers", ext.get_layers, self, image_tag)


    def do_update(self):
        """
        Update AppThreat Vulnerabilty Database.
        """
        rnt.run_with_spinner("Updating db", qry.download_db)

        
    @cmd2.with_argparser(analyze_parser)
    def do_analyze(self, args):
        """
        Analyze a Docker image with all the components.
        """
        if not rnt.is_docker_running():
            print("\033[38;2;241;76;76m[Failure]\033[0m To analyze an image, Docker daemon should be running")
            
            return
        
        image_tag = args.image_tag
        with_trivy = args.with_trivy
        format = args.format
        template = args.template
        output_file = args.output

        if not rnt.is_fetched(image_tag):
            print("\033[38;2;241;76;76m[Failure]\033[0m To analyze an image, it should be fetched first")
            return

        rnt.run_with_spinner("Image setup", run.setup, image_tag, with_trivy)
        rnt.run_with_spinner("Analyzing image", run.analysis, image_tag, with_trivy)
        rnt.run_with_spinner("Generating findings", rpt.get_findings, image_tag, format, output_file, template=template)

        if format == "html":
            rnt.run_with_spinner("Opening findings", rpt.view_findings_html, image_tag, output_file)


    def do_report(self, image_tag):
        """
        Generate LLM report for the analysis conducted on the given Docker image. 
        """
        if not rnt.is_analyzed(image_tag):
            print("\033[38;2;241;76;76m[Failure]\033[0m To generate a report for an image, it should be analyzed first")
            return
        
        rnt.run_with_spinner("Generating report", rpt.report, image_tag)


    def do_cleanup(self, _):
        """
        Remove temporary files created during fetching and scanning.
        """
        rnt.run_with_spinner("Deleting temp files", fld.remove_temp_files)


    def do_clear(self, _):
        """
        Clear the shell output.
        """
        rnt.clear()


    def do_restart(self, _):
        """
        Reload the CLI.
        """
        rnt.restart()


    def do_exit(self, _):
        """
        Exit the PerCIVAl shell.
        """
        return True


if __name__ == "__main__":
    app = Percival()
    app.cmdloop()
