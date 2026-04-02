# most popular distros in 2025
# source: https://www.geeksforgeeks.org/linux-unix/8-most-popular-linux-distributions/
pkgs_dict = {
    "ubuntu": "/var/lib/dpkg/status",
    "debian": "/var/lib/dpkg/status",
    "fedora": "/var/lib/rpm/",
    "centos": "/var/lib/rpm/",
    "arch": "/var/lib/pacman/local/",
    "mint": "/var/lib/dpkg/status",
    "opensuse": "/var/lib/rpm/",
    "rhel": "/var/lib/rpm/",
}

# most used languages in 2024
# source: https://www.statista.com/statistics/793628/worldwide-developer-survey-most-used-languages/
lngs_dict = {
    "javascript": ["package-lock.json", "yarn.lock"],
    "python": ["requirements.txt", "Pipfile.lock", "poetry.lock"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "php": ["composer.json", "composer.lock"],
    "go": ["go.mod", "go.sum"],
    "rust": ["Cargo.toml", "Cargo.lock"],
    "ruby": ["Gemfile", "Gemfile.lock"],
    "r": ["DESCRIPTION", "renv.lock"],
    "dotnet": ["packages.config", "*.csproj", "*.fsproj"],
    "perl": ["cpanfile", "Makefile.PL"],
}