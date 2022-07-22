from dataclasses import dataclass


@dataclass
class ProcessModel:
    name: str
    usage: str
    subprocesses: list
    pid: int
