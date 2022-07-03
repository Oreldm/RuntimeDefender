import inotify.adapters

def _main():
    i = inotify.adapters.InotifyTree('/tmp')

    for event in i.event_gen():
        print(f"A FILE HAVE CHANGED {event}")
        # (_, type_names, path, filename) = event
        #
        # print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
        #     path, filename, type_names))
        pass

if __name__ == '__main__':
    _main()