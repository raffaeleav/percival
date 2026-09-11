<p align="center">
  <img src="https://github.com/user-attachments/assets/5ea818fe-6457-4052-96d6-74e74e8e3f73" width="512" heigth="120">
</p>

<p align="center">
  A Python CLI that scans for vulnerabilities in Docker container images, developed as a project for my Computer Science Master Thesis at the University of Salerno
</p>


## Table of Contents
- [Overview](#Overview)
- [Preview](#Preview)
- [Features](#Features)
- [Requirements](#Requirements)
- [Project structure](#Project-structure)
- [How to replicate](#How-to-replicate)
- [Built with](#Built-with)


## Overview 
<p>
  perCIVAl was build to provide a valuable tool in the context of Vulnerability Assessment of container images. The CLI enables users to fetch a Docker image (given its image tag),
  scan for OS packages / language dependencies vulnerabilities, check for configuration errors and secrets. The vulnerabilites are then included in a structured or natural 
  language report.
</p>


## Preview
<p>
  <img src="https://github.com/user-attachments/assets/617f1f20-c357-4363-827b-4813de5edb6f" width="400" heigth="400">
</p>


## Features
1) Pull a Docker Image
2) Scan with Trivy
3) Scan for OS packages vulnerabilities
4) Scan for language dependencies vulnerabilities
5) Check for configuration errors
6) Regex-based secret detection
7) Entropy-based secret detection
8) Produce structured vulnerability report (html, xml, json, sarif, go templates formats)
9) Produce natural language vulnerability report in pdf format


## Requirements 
- [Docker](https://www.docker.com)
- [Trivy](https://github.com/aquasecurity/trivy)
- Python dependencies are listed in the "requirements.txt" file

## Project structure
```
percival/
│── data/                  
│   ├── images/            # Docker images
│   ├── reports/		   
│   └── temp/              # Image layers
│
│── percival/              
│
│── core/                  # React frontend
│   ├── __init.py__        
│   ├── extract.py	       # Layers / manifest.json extraction
|   ├── fetch.py           # Image pull
│   ├── parse.py           # Database file / language dependencies file parsers
|   ├── report.py.         # Report generation
|   └── scan.py            # Vulnerability scanner
│  
│ 
│── helpers/               
│   ├── __init.py__     
│   ├── api.py             # Vulnerability database queries
|   ├── folders.py__     
│   └── shell.py	       
│
│── .gitignore
|
│── main.py/               # CLI entry point
|
│── README.md
└── requirements.txt
```          


## How to replicate
1) Clone the repository
```bash
git clone https://github.com/raffaeleav/percival.git
```
2) Install dependencies (assuming conda is being used)
```bash
conda create -n "percival"
conda activate percival
pip install -r percival/requirements.txt
```
3) Switch to the project directory
```bash
cd percival
```
4) Start the CLI
```bash
python main.py
```
5) Scan for vulnerabilities
```bash
analyze <image-name>:<tag>
```
7) Produce natural language report
```bash
report <image-name>:<tag>
```

## Built with
- [cmd2](https://cmd2.readthedocs.io/en/latest/) - used for the CLI development
