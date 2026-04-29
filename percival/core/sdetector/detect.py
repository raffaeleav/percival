import os
import re
import json
import numpy as np

from percival.core.dloader import extract as ext
from percival.helpers import folders as fld, runtime as rnt
from percival.core.sdetector import excluded_dirs, excluded_cache_dirs, excluded_exts, key_patterns


def _get_virtual_path(file_path):
    parts = file_path.split(os.sep)

    try:
        sha256_idx = parts.index("sha256")
        virtual_file_path = os.sep + os.sep.join(parts[sha256_idx + 2:])

        return virtual_file_path
    except ValueError:
        return file_path


def _is_excluded(file_path):
    if not isinstance(file_path, str):
        return False
    
    filename = os.path.basename(file_path)
    virtual_file_path = _get_virtual_path(file_path)
        
    for dir in excluded_dirs:
        if virtual_file_path.startswith(dir):
            return True
        
    for dir in excluded_cache_dirs:
        if dir in virtual_file_path:
            return True
        
    for ext in excluded_exts:
        if ext in filename:
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

        if not matched:
            for word in line.split():
                if len(strings) >= max_strings:
                    break

                length = len(word)

                if min_length <= length <= max_length:
                    if _shannon_entropy(word) >= threshold:
                        strings.append(word)
        
    return keys, strings


def _process_file(file_path, min_length, max_length, max_strings, threshold):
    if _is_excluded(file_path):
        return None
    
    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return None
    
    if not lines:
        return None
    
    keys, strings = _get_secrets(lines, min_length, max_length, max_strings, threshold)

    if keys or strings:
        return {"file": file_path, "keys": keys, "strings": strings}
    
    return None


def detect_secrets(image_tag):
    if not rnt.is_fetched(image_tag):
        raise RuntimeError("An unexpected error occurred during secret detection, please fetch the image and try again")
    
    local_tag = fld.sanitize(image_tag)
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), local_tag)
    secrets_file = fld.get_file_path(image_temp_dir, "secrets.json")

    files = ext.get_all_files(image_tag)

    seen = set()
    findings = []

    params = {
        "min_length": 10,
        "max_length": 100,
        "max_strings": 5,
        "threshold": 5.0
    }

    for file_path in files:
        result = _process_file(file_path, **params)

        if result:
            keys = []
            strings = []

            for key in result["keys"]:
                if key["value"] not in seen:
                    seen.add(key["value"])
                    keys.append(key)

            for string in result["strings"]:
                if string not in seen:
                    seen.add(string)
                    strings.append(string)

            if keys or strings:
                result["keys"] = keys
                result["strings"] = strings

                findings.append(result)
                
    with open(secrets_file, "w") as f:
        json.dump(findings, f, indent=2)

    return findings