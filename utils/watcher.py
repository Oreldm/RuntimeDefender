import inotify.adapters

from Models.event_model import EventModel
from utils.settings import MAIN_PATH


class Watcher:
    EVENT_OPEN = 'IN_OPEN'
    EVENT_ACCESS = 'IN_ACCESS'
    EVENT_CLOSE_NO_WRITE = 'IN_CLOSE_NOWRITE'
    EVENT_CLOSE_WRITE = 'IN_CLOSE_WRITE'
    EVENT_DELETE = 'IN_CLOSE_DELETE'
    EVENT_MOVED_FROM = 'IN_MOVED_FROM'
    EVENT_MOVED = 'IN_MOVED'
    EVENT_CREATE = 'IN_CREATE'
    EVENT_ACCESS = 'IN_ACCESS'
    EVENT_MODIFY = 'IN_MODIFY'

    def __init__(self, path_to_watch=MAIN_PATH):
        self.events = []
        self.path_to_watch = path_to_watch

    def watch(self):
        counter = 0
        self.events = []
        i = inotify.adapters.InotifyTree(self.path_to_watch)
        for event in i.event_gen():
            try:
                if event is not None:
                    (_, event_type, path, filename) = event

                    self.events.append(EventModel(path, filename, event_type))
                elif len(self.events) > 0:
                    break
                elif event is None or len(self.events) < 1 and counter == 1000000:
                    break
            except:
                print("An exception while watching directory accrued.")
        return self.events
