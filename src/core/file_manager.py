import json
import os
from datetime import datetime

class FileRecord:
    def __init__(self, original_file, encrypted_file, file_hash, time):
        self.original_file = original_file
        self.encrypted_file = encrypted_file
        self.file_hash = file_hash
        self.time = time

    def to_dict(self):
        return {
            "original_file": self.original_file,
            "encrypted_file": self.encrypted_file,
            "hash": self.file_hash,
            "time": self.time
        }


class FileManager:
    def __init__(self, storage_path="data/metadata.json"):
        self.storage_path = storage_path
        self.records = self.load_records()

    def load_records(self):
        if not os.path.exists(self.storage_path):
            return []

        try:
            with open(self.storage_path, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []

    def save_record(self, record: FileRecord):
        self.records.append(record.to_dict())

        with open(self.storage_path, "w") as f:
            json.dump(self.records, f, indent=4)

    def get_all_records(self):
        return self.records
