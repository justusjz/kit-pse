import json
import re
from src.logging.logger import Logger
from dataclasses import dataclass


class SignatureDb:
    known: list[dict]
    path: str

    def __init__(self, path: str):
        self.path = path
        try:
            with open(path, "r") as f:
                self.known = json.load(f)
                Logger.info(f"Loaded signature database from `{path}`")
        except:
            Logger.error(f"Signature database `{path}` not found")
            self.known = []

    def add_signature(self, pattern: str, description: str):
        self.known.append({"pattern": pattern, "description": description})

    def save(self, path: str | None = None):
        if path == None:
            path = self.path
        with open(path, "w") as f:
            json.dump(self.known, f)
        Logger.info(f"Saved signature database to `{path}`")

    def detect(self, content: bytes) -> str | None:
        for signature in self.known:
            match = re.search(bytes(signature["pattern"], "utf8"), content)
            if match is not None:
                return signature["description"]
        return None
