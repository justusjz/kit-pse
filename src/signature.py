import json
import re

class SignatureDb:
  known: list[tuple[str, str]]
  path: str
  def __init__(self, path: str):
    self.path = path
    try:
      with open(path, "r") as f:
        self.known = json.load(f)
        print(f"Loaded signature database from `{path}`")
    except:
      print(f"Signature database `{path}` not found")
      self.known = []
  
  def add_signature(self, pattern: str, description: str):
    self.known.append((pattern, description))
  
  def save(self, path: str | None = None):
    if path == None:
      path = self.path
    with open(path, "w") as f:
      json.dump(self.known, f)
    print(f"Saved signature database to `{path}`")

  def detect(self, content: bytes) -> str | None:
    for pattern, description in self.known:
      match = re.search(pattern, description)
      if match is not None:
        return description
    return None
