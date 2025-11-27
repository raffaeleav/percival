import os
import docker


def pull(self, image_tag):
    """Pull a Docker image"""
    try:
        client = docker.from_env()

        auth_config = {
            "username": os.getenv("DOCKER_USERNAME"),
            "password": os.getenv("DOCKER_PASSWORD"),
        }

        if auth_config:
            self.params["image"] = client.images.pull(image_tag, auth_config=auth_config)
        else:
            self.params["image"] = client.images.pull(image_tag)

    except Exception:
        raise

    finally:
        client.close()
