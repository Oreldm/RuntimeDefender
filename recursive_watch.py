import inotify.adapters


def _main():
    i = inotify.adapters.InotifyTree('/tmp')

    for event in i.event_gen():
        if event != None:
            (_, type_names, path, filename) = event

            print("PATH=[{}] FILENAME=[{}] EVENT_TYPES={}".format(
                path, filename, type_names))
        pass


if __name__ == '__main__':
    _main()
