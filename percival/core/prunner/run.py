from percival.core.cchecker import check as chk 
from percival.core.sdetector import detect as det 
from percival.core.vscanner import scan as scn, query as qry
from concurrent.futures import ThreadPoolExecutor, as_completed


def setup(image_tag, with_trivy):
    setup_tasks = {
        "update_db": (qry.init_db,),
        "reconstruct_dockerfile": (chk.reconstruct_docker_file, image_tag)
    }

    if with_trivy:
        setup_tasks["update_trivy_db"] = (scn.update_trivy,)

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(fn, *a): label
            for label, (fn, *a) in setup_tasks.items()
        }

        for future in as_completed(futures):
            future.result()


def analysis(image_tag, with_trivy):
    scan_tasks = {
            "scan_pkgs": (scn.scan_os_packages, image_tag),
            "scan_lngs": (scn.scan_language_dependencies, image_tag),
            "check_efficiency": (chk.dive, image_tag),
            "check_dockerfile": (chk.check_config, image_tag),
            "detect_secrets": (det.detect_secrets, image_tag)
        }
    
    if with_trivy:
        scan_tasks["scan_trivy"] = (scn.trivy, image_tag)

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(fn, *a): label
            for label, (fn, *a) in scan_tasks.items()
        }

        for future in as_completed(futures):
            future.result()
