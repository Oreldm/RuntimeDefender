import inotify.adapters

from Models.event_model import EventModel
from utils.settings import MAIN_PATH


class Watcher:

    def __init__(self, path_to_watch=MAIN_PATH):
        self.events = []
        self.path_to_watch = path_to_watch

    def watch(self):
        self.events = []
        i = inotify.adapters.InotifyTree(self.path_to_watch)
        for event in i.event_gen():
            try:
                if event is not None:
                    (_, event_type, path, filename) = event

                    print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
                        path, filename, event_type))
                    self.events.append(EventModel(path, filename, event_type))
                pass
            except:
                print("An exception while watching directory accured.")
        return self.events
