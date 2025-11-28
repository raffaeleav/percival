import os
import json
import tarfile

from percival.helpers import folders as fld
from percival.core.dloader import pkgs_dict, lngs_dict


def get_manifest(self, image_tag):
    if self.params["image"] is None:
        raise RuntimeError("An unexpected error occurred while extracting manifest, please try fetching again")

    images_dir = fld.get_dir(fld.get_data_dir(), "images")
    image_file = fld.get_file_path(images_dir, image_tag + ".tar")
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    with open(image_file, "wb") as f:
        for chunk in self.params["image"].save():
            f.write(chunk)

    with tarfile.open(image_file, "r") as tar:
        tar.extract("manifest.json", path=image_temp_dir)


# this is needed to avoid dangerous that could overwrite files
def get_all_members(layer_tar, layer_dir):
    for member in layer_tar.getmembers():
        if member.islnk() or member.issym():
            if os.path.isabs(member.linkname):
                member.linkname = member.linkname.lstrip("/")
                
        layer_tar.extract(member, path=layer_dir)


def get_layers(self, image_tag):
    if self.params["image"] is None:
        raise RuntimeError("An unexpected error occurred while extracting layers, please try fetching again")

    images_dir = fld.get_dir(fld.get_data_dir(), "images")
    image_file = fld.get_file_path(images_dir, image_tag + ".tar")
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    manifest_file = fld.get_file_path(image_temp_dir, "manifest.json")

    with open(manifest_file, "r") as f:
        manifest = json.load(f)

    layers = manifest[0].get("Layers", [])

    with tarfile.open(image_file, "r") as tar:
        for layer in layers:
            layer_name = layer.replace(".tar", "")

            layer_dir = fld.get_dir(image_temp_dir, layer_name)
            os.makedirs(layer_dir, exist_ok=True)

            layer_member = tar.getmember(layer)
            layer_fileobj = tar.extractfile(layer_member)

            if layer_fileobj:
                with tarfile.open(fileobj=layer_fileobj) as layer_obj:
                    get_all_members(layer_obj, layer_dir)
            else:
                print(f"Extraction failed for layer: {layer_name}")
    
    self.params["image"] = None


def get_all_files(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    layers_dir = fld.get_dir(image_temp_dir, "blobs")
    layers_dir = fld.get_dir(layers_dir, "sha256")

    files = []

    for layer_dir in os.listdir(layers_dir):
        layer_path = os.path.join(layers_dir, layer_dir)
        layer_files = fld.list_files(layer_path)

        for file in layer_files:
            file_path = fld.get_file_path(layer_path, file)
            files.append(file_path)

    return files


def get_pkg_files(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    layers_dir = fld.get_dir(image_temp_dir, "blobs")
    layers_dir = fld.get_dir(layers_dir, "sha256")

    pkg_files = []
    norm_pkgs_dict = [os.path.normpath(p).lstrip(os.sep) for p in pkgs_dict.values()]

    for layer_dir in os.listdir(layers_dir):
        layer_path = os.path.join(layers_dir, layer_dir)
        files = fld.list_files(layer_path)

        for file in files:
            norm_file = os.path.normpath(file)

            if any(pkg_file in norm_file for pkg_file in norm_pkgs_dict):
                pkg_files.append(os.path.join(layers_dir, layer_dir, file))

    return pkg_files


def get_lng_files(image_tag):
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    layers_dir = fld.get_dir(image_temp_dir, "blobs")
    layers_dir = fld.get_dir(layers_dir, "sha256")

    lng_files = []
    norm_lngs_dict = [
        os.path.normpath(p).lstrip(os.sep)
        for v in lngs_dict.values()
        for p in (v if isinstance(v, list) else [v])
    ]

    for layer_dir in os.listdir(layers_dir):
        layer_path = os.path.join(layers_dir, layer_dir)
        files = fld.list_files(layer_path)

        for file in files:
            norm_file = os.path.normpath(file)

            if any(lng_file in norm_file for lng_file in norm_lngs_dict):
                lng_files.append(os.path.join(layers_dir, layer_dir, file))

    return lng_files
