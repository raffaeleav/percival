import os
import docker

from docker.errors import APIError, ImageNotFound, DockerException


def pull(self, image_tag):
    """Pull a Docker image"""
    try:
        client = docker.from_env()

        auth_config = {
            "username": os.getenv("DOCKER_USERNAME"),
            "password": os.getenv("DOCKER_PASSWORD"),
        }

        if auth_config:
            self.params["image"] = client.images.pull(
                image_tag, auth_config=auth_config
            )
        else:
            self.params["image"] = client.images.pull(image_tag)

    except ImageNotFound:
        print(f"Image not found, maybe there's a typo?")
    except APIError as api_err:
        print(f"Docker API error: {api_err}")
    except DockerException as de:
        print(f"Docker error: {de}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    finally:
        client.close()
