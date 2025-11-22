import re
import math
import json

from percival.core import extract as ext
from percival.helpers import folders as fld
from percival.sdetector import excluded_files, excluded_dirs, key_patterns


def is_excluded(file):
    for excluded_file in excluded_files:
        if excluded_file in file:
            return True
        
    for excluded_dir in excluded_dirs:
        if excluded_dir in file:
            return True

    return False


def shannon_entropy(string):
    if not string:
        return 0.0

    freq = {ch: string.count(ch) for ch in set(string)}
    length = len(string)

    entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())

    return entropy


def get_high_entropy_strings(lines, min_length, treshold):
    strings = []

    for line in lines:
        for word in line.split():
            if word.length() < min_length:
                entropy = shannon_entropy(word)

                if entropy >= treshold:
                    strings.append(word)

    return strings


def get_keys(lines):
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
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    secrets_file = fld.get_file_path(image_temp_dir, "secrets.json")

    files = ext.get_all_files(image_tag)

    report = []
    min_length = 20
    # 4.0 is a entropy value that is commonly associated to a "probable" secret
    treshold = 4.0

    for file in files: 
        if is_excluded(file):
            continue

        with open(file, "r") as f:
            lines = f.readlines()

        if lines:
            secrets = get_keys(lines)
            strings = get_high_entropy_strings(lines, min_length, treshold)

            entry = {
                "file": file,
                "secrets": secrets,
                "strings": strings
            }

            report.append(entry)

    with open(secrets_file, "w") as f:
        json.dump(report, f, indent=2)

    return report