import os
import shutil


def setup():
    file_path = os.path.dirname(os.path.abspath(__file__))
    project_path = os.path.abspath(os.path.join(file_path, "..", ".."))
    data_dir = os.path.abspath(os.path.join(project_path, "data"))
    images_dir = os.path.abspath(os.path.join(data_dir, "images"))
    temp_dir = os.path.abspath(os.path.join(data_dir, "temp"))
    reports_dir = os.path.abspath(os.path.join(data_dir, "reports"))

    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(images_dir, exist_ok=True)
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)


def get_module_dir(module):
    file_path = os.path.dirname(os.path.abspath(__file__))
    project_path = os.path.abspath(os.path.join(file_path, "..", ".."))
    module_dir = os.path.abspath(os.path.join(project_path, "percival", module))

    return module_dir


def get_data_dir():
    file_path = os.path.dirname(os.path.abspath(__file__))
    project_path = os.path.abspath(os.path.join(file_path, "..", ".."))
    data_dir = os.path.abspath(os.path.join(project_path, "data"))

    return data_dir


def get_images_dir():
    file_path = os.path.dirname(os.path.abspath(__file__))
    project_path = os.path.abspath(os.path.join(file_path, "..", ".."))
    data_dir = os.path.abspath(os.path.join(project_path, "data"))
    images_dir = os.path.abspath(os.path.join(data_dir, "images"))

    return images_dir


def get_temp_dir():
    file_path = os.path.dirname(os.path.abspath(__file__))
    project_path = os.path.abspath(os.path.join(file_path, "..", ".."))
    data_dir = os.path.abspath(os.path.join(project_path, "data"))
    temp_dir = os.path.abspath(os.path.join(data_dir, "temp"))

    return temp_dir


def get_reports_dir():
    file_path = os.path.dirname(os.path.abspath(__file__))
    project_path = os.path.abspath(os.path.join(file_path, "..", ".."))
    data_dir = os.path.abspath(os.path.join(project_path, "data"))
    reports_dir = os.path.abspath(os.path.join(data_dir, "reports"))

    return reports_dir


def get_dir(dir_path, dir_name):
    path = os.path.abspath(os.path.join(dir_path, dir_name))
    os.makedirs(path, exist_ok=True)

    return path


def get_file_path(dir_path, file_name):
    path = os.path.abspath(os.path.join(dir_path, file_name))

    return path


def list_files(root_dir):
    files = []

    for dir_path, _, file_names in os.walk(root_dir):
        for file_name in file_names:
            file_path = os.path.join(dir_path, file_name)
            rel_file_path = os.path.relpath(file_path, root_dir)

            files.append(rel_file_path)

    return files


def remove_temp_files(image_tag):
    dirs = [
        os.path.join(get_images_dir(), image_tag),
        # os.path.join(get_reports_dir(), image_tag),
        os.path.join(get_temp_dir(), image_tag),
    ]

    for dir in dirs:
        if os.path.exists(dir):
            shutil.rmtree(dir)
