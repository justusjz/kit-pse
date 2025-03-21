import os
import requests
from src.logging.logger import Logger


def download_file(url, local_path):
    """Downloads the file from the given url to the local path.
    If the local path already exists, no download takes place
    """
    if not os.path.exists(local_path):
        Logger.info(f"Download file from  {url}.")
        r = requests.get(url)
        r.raise_for_status()  # raise error if download failed
        with open(local_path, "wb") as f:
            f.write(r.content)
        Logger.info("Download finished.")
    else:
        Logger.info(f"{local_path} already exists.")
