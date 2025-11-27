from percival.helpers import api
from percival.vscanner import parse as prs


def scan_javascript_package_json(lng_file):
    dependencies = prs.parse_javascript_package_json(lng_file)
    results = api.query_osv(dependencies)

    return results


def scan_python_requirements_txt(lng_file):
    dependencies = prs.parse_python_requirements_txt(lng_file)

    results = api.query_osv(dependencies)

    return results


def scan_java_pom_xml(lng_file):
    dependencies = prs.parse_java_pom_xml(lng_file)
    results = api.query_osv(dependencies)

    return results


lng_handlers = {
    ("javascript", "package.json"): scan_javascript_package_json,
    ("python", "requirements.txt"): scan_python_requirements_txt,
    ("java", "pom.xml"): scan_java_pom_xml,
}


def get_lng_vulns(language, file_type, lng_file):
    handler = lng_handlers.get((language, file_type))
    if handler:
        return handler(lng_file)
    else:
        return None