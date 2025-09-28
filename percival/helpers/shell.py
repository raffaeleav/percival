import subprocess


def run_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"{result.stderr}")

    return result.stdout
