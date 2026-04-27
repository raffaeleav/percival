from percival.core.cchecker import check as chk 
from percival.core.sdetector import detect as det 
from percival.core.vscanner import scan as scn, query as qry
from concurrent.futures import ThreadPoolExecutor, as_completed


def setup(image_tag, targets, with_trivy):
    setup_tasks = {}

    if "v" in targets:
        setup_tasks["update_db"] = (qry.init_db,)

    if "c" in targets:
        setup_tasks["reconstruct_dockerfile"] = (chk.reconstruct_dockerfile, image_tag)

    if with_trivy:
        setup_tasks["update_trivy_db"] = (scn.update_trivy,)

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(fn, *a): label
            for label, (fn, *a) in setup_tasks.items()
        }

        for future in as_completed(futures):
            future.result()


def analysis(image_tag, targets, with_trivy):
    scan_tasks = {}

    if "v" in targets:
        scan_tasks["scan_pkgs"] = (scn.scan, image_tag, "pkgs")
        scan_tasks["scan_lngs"] = (scn.scan, image_tag, "lngs")

    if "c" in targets:
        scan_tasks["check_efficiency"] = (chk.dive, image_tag)
        scan_tasks["check_dockerfile"] = (chk.check_config, image_tag)

    if "s" in targets:
        scan_tasks["detect_secrets"] = (det.detect_secrets, image_tag)
    
    if with_trivy:
        scan_tasks["scan_trivy"] = (scn.trivy, image_tag)

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(fn, *a): label
            for label, (fn, *a) in scan_tasks.items()
        }

        for future in as_completed(futures):
            future.result()
