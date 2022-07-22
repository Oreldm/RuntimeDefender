from dataclasses import dataclass


@dataclass
class EventModel:
    path: str
    filename: str
    event_type: str
