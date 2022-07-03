import inotify.adapters


def _main():
    watcher('/home/orel')
    watcher('/tmp')
    watcher('/bin')


def watcher(path: str):
    i = inotify.adapters.InotifyTree(path)
    for event in i.event_gen():
        try:
            if event != None:
                (_, type_names, path, filename) = event

                print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
                    path, filename, type_names))
            pass
        except:
            pass


if __name__ == '__main__':
    _main()
