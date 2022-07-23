from utils.rabbit_controller import RabbitMqController
from utils.tools import Tools
from utils.verifier import Verifier
from utils.watcher import Watcher

if __name__ == "__main__":
    """
        1. Get all md5 of /bin
        2. Watch changes in loop
        3. Every change get list of events
        4. Go over the event- find the file
        5. Check if the file changed
        6. Check if its cryptominer -> by strings/ filename. 
        7. Check if the file is in a md5 database of malicious feed
        8. do ps -a
        9. Check if there is a reverse_shell
        10. do tcpdump, check if there is malicious ip / domain
        11. If one of the above is true: Write it to the screen.
        12. EVERY 1 MIN add cpu usage for a map of ps. Check if something is weird (cryptominer). After 30min delete
            last one.
    """
    verifier = Verifier()
    tools = Tools()
    watcher = Watcher()
    files_dict = tools.get_md5()
    resources = []
    alerts = []
    while True:
        controller = RabbitMqController()
        alerts.extend(verifier.verify_malware_dict(files_dict, is_send_to_rabbit=True))
        for alert in alerts:
            controller.send_alert(alert)
        controller.connection.close()
        events = watcher.watch()
        alert_from_verifier, resources = verifier.verify_resources(resources, is_send_to_rabbit=True)
        alerts.extend(alert_from_verifier)
        alerts.extend(verifier.verify_filesystem_event(events, is_send_to_rabbit=True))
        alerts.extend(verifier.verify_cryptominer(events, is_send_to_rabbit=True))
        alerts.extend(verifier.verify_reverse_shell(events, is_send_to_rabbit=True))
        alerts.extend(verifier.verify_request(is_send_to_rabbit=True))
        files_dict = tools.get_md5()


