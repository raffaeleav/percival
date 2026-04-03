dockerfile_commands = ("RUN", "CMD", "ENTRYPOINT", "COPY", "ADD", "ENV", "WORKDIR")
run_regex = r'^(/bin/bash|/bin/sh)\s+-c\s+'