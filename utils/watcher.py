import inotify.adapters

from Models.event_model import EventModel


class Watcher:

    def __init__(self, path_to_watch='/bin'):
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
                return self.events
