from vdb.lib import search
from vdb.lib import config, db6 as db_lib
from vdb.lib.orasclient import download_image


def download_db():
    db_url = config.VDB_DATABASE_URL
    
    download_image(db_url, config.DATA_DIR)


def is_updated():
    return db_lib.needs_update(days=1)


def init_db():
    if not is_updated():
        download_db()


def search_by_purl(purl):
    results = search.search_by_purl_like(purl, with_data=True)

    cves = []
    seen = set()

    for result in results:
        cve_id = result.get("cve_id")
        source = result.get("source_data")
        
        if not cve_id or cve_id in seen:
            continue

        seen.add(cve_id)

        metrics = source.root.containers.cna.metrics.root if source.root.containers.cna.metrics else []
        severity = None
        score = None
        vector = None
        
        if metrics:
            for metric in metrics:
                if metric.cvssV3_1:
                    score = float(metric.cvssV3_1.baseScore.root)
                    severity = metric.cvssV3_1.baseSeverity.value
                    vector = metric.cvssV3_1.vectorString

                    break
                elif metric.cvssV3_0:
                    score = float(metric.cvssV3_0.baseScore.root)
                    severity = metric.cvssV3_0.baseSeverity.value
                    vector = metric.cvssV3_0.vectorString

                    break
                elif metric.cvssV2_0:
                    score = float(metric.cvssV2_0.baseScore.root)
                    severity = metric.cvssV2_0.baseSeverity.value
                    vector = metric.cvssV2_0.vectorString

                    break
        
        cves.append({
            "id": cve_id,
            "severity": severity,
            "cvss_base_score": score,
            "cvss_vector": vector
        })
    
    return cves