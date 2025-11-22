excluded_files = {}

excluded_dirs = {}

key_patterns = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|key).{0,5}[0-9A-Za-z/+]{40}",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9._-]+?\.[a-zA-Z0-9._-]+",
}