from dataclasses import dataclass


@dataclass
class FileModel:
    name: str
    md5: str

    def get_strings(self):
        pass
