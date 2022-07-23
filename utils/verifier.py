# from utils.watcher import Watcher


class Verifier:
    feed_arr = None
    def check_if_alert(self):
        pass

    def verify_cryptominer(self):
        pass

    def verify_reverse_shell(self):
        pass

    def verify_binaries(self):
        pass

    def verify_request(self):
        """ This function verify output request """
        pass

    def verify_malware(self, md5: str):
        if self.feed_arr is None:
            pass
        pass

    # def verify_filesystem_event(self, events: list):
    #     for event in events:
    #         if Watcher.EVENT_CREATE in event.event_type:
    #             print(f"FILE {event.filename} has created")
    #         elif Watcher.EVENT_DELETE in event.event_type or Watcher.EVENT_MOVED_FROM in event.event_type:
    #             print(f"FILE {event.filename} has deleted")
    #         elif Watcher.EVENT_CLOSE_WRITE in event.event_type or Watcher.EVENT_MODIFY in event.event_type:
    #             print(f"FILE {event.filename} has been modified")
    #         elif (Watcher.EVENT_ACCESS in event.event_type or Watcher.EVENT_ACCESS in event.event_type) \
    #                 and 'sudo' == event.filename:
    #             print(f"SUDO PERMISSION HAS BEEN ACCESSED")
    #         elif Watcher.EVENT_MOVED in event.event_type:
    #             print(f"FILE {event.filename} has moved")



