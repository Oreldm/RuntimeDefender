from utils.tools import Tools
from utils.verifier import Verifier
from utils.watcher import Watcher

if __name__ == "__main__":
    """
        This is the OnPrem Client!
        No Need a server for this one!
    
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
    while True:
        verifier.verify_malware_dict(files_dict)
        events = watcher.watch()
        _, resources = verifier.verify_resources(resources)
        verifier.verify_filesystem_event(events)
        verifier.verify_cryptominer(events)
        verifier.verify_reverse_shell(events)
        verifier.verify_request()
        files_dict = tools.get_md5()


