import json
import os
from dataclasses import dataclass, asdict


DATA_DIR = "data"
DATA_FILE = os.path.join(DATA_DIR, "metadata.json")


@dataclass
class FileRecord:
    original_file: str
    encrypted_file: str
    file_hash: str
    time: str


class FileManager:

    def __init__(self):
        os.makedirs(DATA_DIR, exist_ok=True)

        if not os.path.exists(DATA_FILE):
            with open(DATA_FILE, "w") as f:
                json.dump([], f)

    def save_record(self, record: FileRecord):

        records = self.get_all_records()   # reload fresh each time
        records.append(asdict(record))

        with open(DATA_FILE, "w") as f:
            json.dump(records, f, indent=4)
    
    def to_dict(self):
        return {
            "original_file": self.original_file,
            "encrypted_file": self.encrypted_file,
            "file_hash": self.file_hash,  # <- now consistent with GUI
            "time": self.time
        }
    
    def get_all_records(self):

        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except:
            return []
