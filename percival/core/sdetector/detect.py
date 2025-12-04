import re
import math
import json

from percival.core.dloader import extract as ext
from percival.helpers import folders as fld, runtime as rnt
from percival.core.sdetector import excluded_files, excluded_dirs, key_patterns


def _is_excluded(file):
    if not isinstance(file, str):
        return False
    
    for excluded_file in excluded_files:
        if excluded_file in file:
            return True
        
    for excluded_dir in excluded_dirs:
        if excluded_dir in file:
            return True

    return False


def _shannon_entropy(string):
    if not isinstance(string, str):
        return 0.0

    freq = {ch: string.count(ch) for ch in set(string)}
    length = len(string)

    entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())

    return entropy


def _get_high_entropy_strings(lines, min_length, treshold=4.5):
    if not lines or not min_length:
        return []

    strings = []

    for line in lines:
        for word in line.split():
            if len(word) >= min_length:
                entropy = _shannon_entropy(word)

                if entropy >= treshold:
                    strings.append(word)

    return strings


def _get_keys(lines):
    if not lines:
        return []
    
    keys = []
    
    for line in lines:
        for key_type, pattern in key_patterns.items():
            match = re.search(pattern, line)

            if match:
                entry = {
                    "key_type": key_type,
                    "value": match.group(0),
                }

                keys.append(entry)

    return keys


def detect_secrets(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred during secret detection, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    secrets_file = fld.get_file_path(image_temp_dir, "secrets.json")

    files = ext.get_all_files(image_tag)

    report = []
    min_length = 20
    # 5.0 is a entropy value that is commonly associated to a secret with medium probability
    treshold = 5.0

    for file in files: 
        if _is_excluded(file):
            continue
        
        try:
            with open(file, "r", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            continue

        if lines:
            keys = _get_keys(lines)
            strings = _get_high_entropy_strings(lines, min_length, treshold)

            if keys or strings:
                entry = {
                    "file": file,
                    "keys": keys,
                    "strings": strings
                }

                report.append(entry)

    with open(secrets_file, "w") as f:
        json.dump(report, f, indent=2)

    return report