from utils.settings import MAIN_PATH
from utils.tools import Tools
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
        
        FORWARD:
            1. EVERY 1 MIN add cpu usage for a map of ps. Check if something is weird (cryptominer). After 30min delete
            last one.
            2. Do tcpdump in parallel, ps -a in parallel, and file changes in parallel.
            3. Seperate to client and server.
            4. Build GUI.
    """
    tools = Tools()
    files_dict = tools.get_md5()

    watcher = Watcher()
    while True:
        events = watcher.watch()
        new_files_dict = tools.get_md5()
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

            #if new_files_dict != files_dict:
             #   print(f"FILE {event.filename} has changed")
              #  files_dict = new_files_dict

            #print(f"FILE: {event.filename} TYPE: {event.event_type}")
