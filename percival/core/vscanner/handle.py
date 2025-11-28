import os

from percival.helpers import api
from percival.core.vscanner import parse as prs


def _scan_javascript_package_json(lng_file):
    if not isinstance(lng_file, (str, bytes, os.PathLike)):
        raise TypeError(f"lng_file must be a path-like object, got {type(lng_file).__name__} instead")
    
    dependencies = prs.parse_javascript_package_json(lng_file)
    results = api.query_osv(dependencies)

    return results


def _scan_python_requirements_txt(lng_file):
    if not isinstance(lng_file, (str, bytes, os.PathLike)):
        raise TypeError(f"lng_file must be a path-like object, got {type(lng_file).__name__} instead")
    
    dependencies = prs.parse_python_requirements_txt(lng_file)

    results = api.query_osv(dependencies)

    return results


def _scan_java_pom_xml(lng_file):
    if not isinstance(lng_file, (str, bytes, os.PathLike)):
        raise TypeError(f"lng_file must be a path-like object, got {type(lng_file).__name__} instead")
    
    dependencies = prs.parse_java_pom_xml(lng_file)
    results = api.query_osv(dependencies)

    return results


lng_handlers = {
    ("javascript", "package.json"): _scan_javascript_package_json,
    ("python", "requirements.txt"): _scan_python_requirements_txt,
    ("java", "pom.xml"): _scan_java_pom_xml,
}


def get_lng_vulns(language, file_type, lng_file):
    if not isinstance(lng_file, (str, bytes, os.PathLike)):
        raise TypeError(f"lng_file must be a path-like object, got {type(lng_file).__name__} instead")
    
    handler = lng_handlers.get((language, file_type))

    if handler:
        return handler(lng_file)
    else:
        return None