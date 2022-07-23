from Models.resource_model import ResourceModel
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
                full_path = f"{MAIN_PATH}/{event.filename}"
                ret = self.tools.terminal_command(f"strings {MAIN_PATH}/{event.filename}", is_print_error=False)
                ret = ret.split('\n')
                suspicious_strings = [x for x in ret if x.lower() in list_of_cryptominers_strings]
                if len(suspicious_strings) > 0:
                    print(f"{alert_message} Verified by checking its inner strings.")
                    return
            except:
                continue

    def verify_reverse_shell(self, events: list):
        """
            This catch reverse shell and bind shell
        :param events:
        :return:
        """
        list_of_suspicious_reverse_shell_spawn = ['/bin/bash -i', '/bin/sh -i', 'nc -nlvp', 'nc -e', '-e /bin/bash']
        list_of_suspicious_files = ['dash', 'bash', 'sh', 'nc', 'netcat', 'ncat']
        for event in events:
            if event.filename in list_of_suspicious_files:
                ret = self.tools.terminal_command("ps -ef")
                reverse_shell_spawn = [x for x in list_of_suspicious_reverse_shell_spawn if x in ret]
                if len(reverse_shell_spawn) > 0:
                    print("Suspicious reverse shell on the machine. Check for these processes and close them if needed:"
                          f" {reverse_shell_spawn}")

    def verify_request(self):
        """
        This function verify output request
        List of dengerous domain according to
        https://www.xfer.com/newsletter-content/10-of-the-most-dangerous-domains-on-the-web.html
        """
        list_of_dangerous_domains= ['.zip','.review', '.country', '.kim', '.cricket','.sceince', '.work', 'party',
                                    '.gq', '.link']
        ret = self.tools.terminal_command("timeout 2 tcpdump")
        danger_domains_arr = [x for x in list_of_dangerous_domains if x in ret]
        if len(danger_domains_arr) > 0:
            print(f"Suspicious request! To the domain with acronym {danger_domains_arr}. Full tcpdump: {ret}")

    def verify_resources(self, resources=[]):
        if len(resources) > 9:
            cpu_usage = 0.0
            ram_usage = 0.0
            for resource in resources:
                cpu_usage += resource.cpu
                ram_usage += resource.memory
            cpu_medium = cpu_usage / 10
            ram_medium = ram_usage / 10
            if cpu_medium > 89.0 or ram_medium < 10.0:
                print(f"Suspecioud Cryptominer on the machine. Look over your cpu/ram usage. Ram: {ram_medium}. "
                      f"Cpu: {cpu_medium}")
            resources = [x for x in resources if x is not resources[0]]

        cpu_str = self.tools.terminal_command("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END "
                                              "{print usage}'")
        cpu_float = float(cpu_str)

        memory_str = self.tools.terminal_command("cat /proc/meminfo | grep MemFree")
        memory_str = memory_str.split()[1]
        memory_float = float(memory_str)
        resources.append(ResourceModel(cpu_float, memory_float))
        return resources

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
            event.path = event.path.replace('/X11', "")
            if Watcher.EVENT_CREATE in event.event_type:
                print(f"FILE {event.path}/{event.filename} has created")
            elif Watcher.EVENT_DELETE in event.event_type or Watcher.EVENT_MOVED_FROM in event.event_type:
                print(f"FILE {event.path}/{event.filename} has deleted")
            elif Watcher.EVENT_CLOSE_WRITE in event.event_type or Watcher.EVENT_MODIFY in event.event_type:
                print(f"FILE {event.path}/{event.filename} has been modified")
            elif (Watcher.EVENT_ACCESS in event.event_type or Watcher.EVENT_ACCESS in event.event_type) \
                    and 'sudo' == event.filename:
                print(f"SUDO PERMISSION HAS BEEN ACCESSED")
            elif Watcher.EVENT_MOVED in event.event_type:
                print(f"FILE {event.path}/{event.filename} has moved")
