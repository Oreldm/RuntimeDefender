from utils.settings import MAIN_PATH
from utils.tools import Tools
from utils.watcher import Watcher


class Verifier:
    def __init__(self):
        self.feed_arr = None
        self.tools = Tools()

    def verify_cryptominer(self, events: list):
        list_of_cryptominers_strings = ['xmrig', 'cryptominer', 'crypto', 'miner', 'csminer', 'nbminer', 'xmr',
                                        'sonarlint', 'monero', 'randomx', 'turtle', 'coin']
        for event in events:
            try:
                alert_message = f"File {event.filename} is a suspicious crypto miner."
                if str(event.filename).lower() in list_of_cryptominers_strings:
                    print(f"{alert_message} Verified by name.")
                    return
                ret = self.tools.terminal_command(f"strings {MAIN_PATH}/{event.filename}")
                ret = ret.split('\n')
                suspicious_strings = [x for x in ret if x.lower() in list_of_cryptominers_strings]
                if len(suspicious_strings) > 0:
                    print(f"{alert_message} Verified by checking its inner strings.")
                    return
            except:
                continue

    def verify_reverse_shell(self, events: list):
        pass

    def verify_request(self):
        """ This function verify output request """
        pass

    def verify_cpu(self):
        pass


    def verify_malware_dict(self, files_md5_dict: dict):
        for file_name, md5 in files_md5_dict.items():
            if self.verify_malware(md5):
                print(f"File {file_name} is a malware!")

    def verify_malware(self, md5: str):
        if self.feed_arr is None:
            # Loading the feed to the memory only once
            self.feed_arr = self.tools.get_malware_feed()
        return md5 in self.feed_arr

    # noinspection PyMethodMayBeStatic
    def verify_filesystem_event(self, events: list):
        for event in events:
            if Watcher.EVENT_CREATE in event.event_type:
                print(f"FILE {event.filename} has created")
            elif Watcher.EVENT_DELETE in event.event_type or Watcher.EVENT_MOVED_FROM in event.event_type:
                print(f"FILE {event.filename} has deleted")
            elif Watcher.EVENT_CLOSE_WRITE in event.event_type or Watcher.EVENT_MODIFY in event.event_type:
                print(f"FILE {event.filename} has been modified")
            elif (Watcher.EVENT_ACCESS in event.event_type or Watcher.EVENT_ACCESS in event.event_type) \
                    and 'sudo' == event.filename:
                print(f"SUDO PERMISSION HAS BEEN ACCESSED")
            elif Watcher.EVENT_MOVED in event.event_type:
                print(f"FILE {event.filename} has moved")
