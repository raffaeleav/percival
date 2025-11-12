<p align="center">
  <img src="https://github.com/user-attachments/assets/ef0f428f-1e7f-43a6-b0c1-d6adfb9b590b" width="512" heigth="120">
</p>


<p align="center">
  A Python CLI that scans for vulnerabilities in Docker container images, developed as a project for the Penetration Testing and Ethical Hacking course, part of the Computer Science Master's Degree program at the University of Salerno
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
    perCIVAl was build to provide a valuable tool in the context of Vulnerability Assessment of container images. The CLI enables users to fetch a Docker image (given its image name and tag), scan for OS packages / language dependencies vulnerabilities and then produce a report.
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
5) Generate report
6) Delete temp files (such as image layers and manifest.json)


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
5) Fetch an image (assuming Docker daemon it's running)
```bash
fetch <image-name>:<tag>
```
6) Scan for vulnerabilities
```bash
vscan <image-name>:<tag>
```
7) Generate report (found in percival/data/reports directory)
```bash
report <image-name>:<tag>
```

## Built with
- [cmd2](https://cmd2.readthedocs.io/en/latest/) - used for the CLI development
