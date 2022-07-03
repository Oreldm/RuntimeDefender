import inotify.adapters


def _main():
    i = inotify.adapters.InotifyTree('/')

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
