from Models.alert_model import Alert
from Models.resource_model import ResourceModel
from utils.settings import MAIN_PATH
from utils.tools import Tools
from utils.watcher import Watcher


class Verifier:
    def __init__(self):
        self.feed_arr = None
        self.tools = Tools()

    def verify_cryptominer(self, events: list, is_send_to_rabbit=False):
        """
        Verifying cryptominer by one of these strings/files -> inside the file and using its name:
        'xmrig', 'cryptominer', 'crypto', 'miner', 'csminer', 'nbminer', 'xmr',
                                        'sonarlint', 'monero', 'randomx', 'turtle', 'coin'

        :param events: list of events
        :param is_send_to_rabbit: is should send to rabbit
        :return: Alerts arr
        """
        list_of_cryptominers_strings = ['xmrig', 'cryptominer', 'crypto', 'miner', 'csminer', 'nbminer', 'xmr',
                                        'sonarlint', 'monero', 'randomx', 'turtle', 'coin']
        alerts = []
        for event in events:
            try:
                alert_message = f"File {event.filename} is a suspicious crypto miner."
                if str(event.filename).lower() in list_of_cryptominers_strings:
                    alert_str = f"{alert_message} Verified by name."
                    print(alert_str)
                    if is_send_to_rabbit:
                        alerts.append(Alert("CryptominerAlert",alert_str))
                    return alerts
                full_path = f"{MAIN_PATH}/{event.filename}"
                ret = self.tools.terminal_command(f"strings {full_path}", is_print_error=False)
                ret = ret.split('\n')
                suspicious_strings = [x for x in ret if x.lower() in list_of_cryptominers_strings]
                if len(suspicious_strings) > 0:
                    alert_str = f"{alert_message} Verified by checking its inner strings."
                    print(alert_str)
                    if is_send_to_rabbit:
                        alerts.append(Alert("CryptominerAlert",alert_str))
                    return alerts
            except:
                continue
        return alerts

    def verify_reverse_shell(self, events: list, is_send_to_rabbit=False):
        """
            This catch reverse shell and bind shell
        :param events: list of events
        :return: Alerts arr
        """
        alerts = []
        list_of_suspicious_reverse_shell_spawn = ['/bin/bash -i', '/bin/sh -i', 'nc -nlvp', 'nc -e', '-e /bin/bash']
        ret = self.tools.terminal_command("ps -ef")
        reverse_shell_spawn = [x for x in list_of_suspicious_reverse_shell_spawn if x in ret]
        if len(reverse_shell_spawn) > 0:
            alert_str = "Suspicious reverse shell on the machine. Check for these " \
                        f"processes and close them if needed: {reverse_shell_spawn}"
            print(alert_str)
            if is_send_to_rabbit:
                alerts.append(Alert("ReverseShellAlert",alert_str))
        return alerts

    def verify_request(self, is_send_to_rabbit=False):
        """
        This function verify output request
        List of dangerous domain according to
        https://www.xfer.com/newsletter-content/10-of-the-most-dangerous-domains-on-the-web.html

        I do here tcpdump for 2 seconds catch all requests and check if it has one of the domains that are dangerous
        """
        alerts = []
        try:
            list_of_dangerous_domains = ['.zip', '.review', '.country', '.kim', '.cricket', '.sceince', '.work', 'party',
                                         '.gq', '.link']
            ret = self.tools.terminal_command("timeout 2 tcpdump", is_print_error=False)
            if ret is not None:
                danger_domains_arr = [x for x in list_of_dangerous_domains if x in ret]
                if len(danger_domains_arr) > 0:
                    alert_str = f"Suspicious request! To the domain with acronym {danger_domains_arr}. Full tcpdump: {ret}"
                    print(alert_str)
                    if is_send_to_rabbit:
                        alerts.append(Alert("NetworkRequestAlert", alert_str))
        except:
            pass
        return alerts

    def verify_resources(self, resources=[], is_send_to_rabbit=False):
        """
        Verify if for 10 times we have high usage of cpu or memory.
        If so - a cryptominer is suspected.
        :param resources: resources array
        :param is_send_to_rabbit: true/false
        :return: Alerts , Resources touple
        """
        alerts = []
        if len(resources) > 9:
            cpu_usage = 0.0
            ram_usage = 0.0
            for resource in resources:
                cpu_usage += resource.cpu
                ram_usage += resource.memory
            cpu_medium = cpu_usage / 10
            ram_medium = ram_usage / 10
            if cpu_medium > 89.0 or ram_medium < 10.0:
                alert_str = f"Suspecioud Cryptominer on the machine. Look over your cpu/ram usage. Ram: " \
                            f"{ram_medium}. Cpu: {cpu_medium}"
                print(alert_str)
                if is_send_to_rabbit:
                    alerts.append(Alert("ResourcesAlert",alert_str))
            resources = [x for x in resources if x is not resources[0]]

        cpu_str = self.tools.terminal_command("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END "
                                              "{print usage}'")
        cpu_float = float(cpu_str)

        memory_str = self.tools.terminal_command("cat /proc/meminfo | grep MemFree")
        memory_str = memory_str.split()[1]
        memory_float = float(memory_str)
        resources.append(ResourceModel(cpu_float, memory_float))
        return alerts, resources

    def verify_malware_dict(self, files_md5_dict: dict, is_send_to_rabbit=False):
        """
        Test md5 of /bin infront of malware feed.
        :param files_md5_dict: md5 dict of file,md5 of /bin
        :param is_send_to_rabbit: True/False
        :return: Alerts Arr
        """
        alerts = []
        for file_name, md5 in files_md5_dict.items():
            if self.verify_malware(md5):
                alert_str = f"File {file_name} is a malware!"
                print(alert_str)
                if is_send_to_rabbit:
                    alerts.append(Alert("MalwareAlert", alert_str))
        return alerts

    def verify_malware(self, md5: str):
        """
        Veriying if md5 is a malware
        :param md5: string
        :return: True/False
        """
        if self.feed_arr is None:
            # Loading the feed to the memory only once
            self.feed_arr = self.tools.get_malware_feed()
        return md5 in self.feed_arr

    # noinspection PyMethodMayBeStatic
    def verify_filesystem_event(self, events: list, is_send_to_rabbit=False):
        """
        Verify if there are changes in the filesystem (in /bin)
        :param events: events arr
        :param is_send_to_rabbit: True/False
        :return: Alerts Arr
        """
        alerts = []
        for event in events:
            event.path = event.path.replace('/X11', "")
            if Watcher.EVENT_CREATE in event.event_type:
                alert_str = f"FILE {event.path}/{event.filename} has created"
                print(alert_str)
                if is_send_to_rabbit:
                    alerts.append(Alert("FilesystemAlert",alert_str))
            elif Watcher.EVENT_DELETE in event.event_type or Watcher.EVENT_MOVED_FROM in event.event_type:
                alert_str = f"FILE {event.path}/{event.filename} has deleted"
                print(alert_str)
                if is_send_to_rabbit:
                    alerts.append(Alert("FilesystemAlert",alert_str))
            elif Watcher.EVENT_CLOSE_WRITE in event.event_type or Watcher.EVENT_MODIFY in event.event_type:
                alert_str = f"FILE {event.path}/{event.filename} has been modified"
                print(alert_str)
                if is_send_to_rabbit:
                    alerts.append(Alert("FilesystemAlert",alert_str))
            elif (Watcher.EVENT_ACCESS in event.event_type or Watcher.EVENT_ACCESS in event.event_type) \
                    and 'sudo' == event.filename:
                alert_str = f"SUDO PERMISSION HAS BEEN ACCESSED"
                print(alert_str)
                if is_send_to_rabbit:
                    alerts.append(Alert("FilesystemAlert",alert_str))
            elif Watcher.EVENT_MOVED in event.event_type:
                alert_str = f"FILE {event.path}/{event.filename} has moved"
                print(alert_str)
                if is_send_to_rabbit:
                    alerts.append(Alert("FilesystemAlert",alert_str))

        return alerts
