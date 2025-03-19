import os
import requests


def download_file(url, local_path):
    """Downloads the file from the given url to the local path.
    If the local path already exists, no download takes place
    """
    if not os.path.exists(local_path):
        print(f"Download file from  {url}.")
        r = requests.get(url)
        r.raise_for_status()  # raise error if download failed
        with open(local_path, "wb") as f:
            f.write(r.content)
        print("Download finished.")
    else:
        print(f"{local_path} already exists.")
