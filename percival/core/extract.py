import os
import json
import tarfile

from percival.helpers import folders as fld
from percival.core import pkgs_dict, lngs_dict


def get_manifest(self, image_tag):
    if self.params["image"] is None:
        print("An error occured while extracting manifest, please try again")
        return

    images_dir = fld.get_dir(fld.get_data_dir(), "images")
    image_file = fld.get_file_path(images_dir, image_tag + ".tar")
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)

    with open(image_file, "wb") as f:
        for chunk in self.params["image"].save():
            f.write(chunk)

    with tarfile.open(image_file, "r") as tar:
        try:
            tar.extract("manifest.json", path=image_temp_dir)
        except KeyError:
            print(
                "manifest.json not found in tar archive, is your image built correctly?"
            )


def get_layers(self, image_tag):
    if self.params["image"] is None:
        print("An error occured while extracting image layers, please try again")
        return

    images_dir = fld.get_dir(fld.get_data_dir(), "images")
    image_file = fld.get_file_path(images_dir, image_tag + ".tar")
    image_temp_dir = fld.get_dir(fld.get_temp_dir(), image_tag)
    manifest_file = fld.get_file_path(image_temp_dir, "manifest.json")

    with open(manifest_file, "r") as f:
        manifest = json.load(f)

    layers = manifest[0].get("Layers", [])

    with tarfile.open(image_file, "r") as tar:
        for layer in layers:
            layer_member = tar.getmember(layer)

            layer_dir = os.path.abspath(
                os.path.join(image_temp_dir, layer.replace(".tar", ""))
            )
            os.makedirs(layer_dir, exist_ok=True)

            layer_fileobj = tar.extractfile(layer_member)

            if layer_fileobj:
                with tarfile.open(fileobj=layer_fileobj) as layer_obj:
                    layer_obj.extractall(path=layer_dir)
            else:
                print(f"Extraction failed for layer: {layer.replace(".tar", "")}")


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
