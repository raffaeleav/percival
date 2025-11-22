from percival.core import extract as ext
from percival.sdetector import excluded_files, excluded_dirs, key_patterns


def get_keys(file):
    return None


def get_high_entropy_strings(file):
    return None


def detect_secrets(image_tag):
    files = ext.get_all_files(image_tag)

    report = []

    for file in files: 
        secrets = get_keys(file)
        strings = get_high_entropy_strings(file)

        entry = {
            "file": file,
            "secrets": secrets,
            "strings": strings
        }

        report.append(entry)

    return report