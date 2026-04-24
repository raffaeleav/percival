import re
import json
import numpy as np

from percival.helpers import pool as pol
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
    counts = np.frombuffer(string.encode(), dtype=np.uint8)
    _, freq = np.unique(counts, return_counts=True)
    probs = freq / len(string)

    return -np.sum(probs * np.log2(probs))


def _get_secrets(lines, min_length, max_length, max_strings, threshold=4.5):
    if not lines or not min_length or not max_length:
        return [], []
    
    strings = []
    keys = []
    
    for line in lines:
        matched = False

        for key_type, pattern in key_patterns.items():
            match = re.search(pattern, line)

            if match:
                keys.append({
                    "key_type": key_type,
                    "value": match.group(0),
                })

                matched = True

        if not matched and len(strings) < max_strings:
            for word in line.split():
                length = len(word)

                if min_length <= length <= max_length:
                    if _shannon_entropy(word) >= threshold:
                        strings.append(word)
        
    return keys, strings


def _process_file(file, min_length, max_length, max_strings, threshold):
    if _is_excluded(file):
        return None
    
    try:
        with open(file, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None
    
    if not lines:
        return None
    
    keys, strings = _get_secrets(lines, min_length, max_length, max_strings, threshold)

    if keys or strings:
        return {"file": file, "keys": keys, "strings": strings}
    
    return None


def detect_secrets(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred during secret detection, please fetch the image and try again")
    
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    secrets_file = fld.get_file_path(image_temp_dir, "secrets.json")

    files = ext.get_all_files(image_tag)

    findings = []

    params = {
        "min_length": 20,
        "max_length": 500,
        "max_strings": 5,
        "threshold": 5.0
    }

    for file_path in files:
        result = _process_file(file_path, **params)

        if result:
            findings.append(result)
                
    with open(secrets_file, "w") as f:
        json.dump(findings, f, indent=2)

    return findings