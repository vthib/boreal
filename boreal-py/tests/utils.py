import os
from threading import Lock

import boreal


def modules_distinct():
    if "BOREAL_PY_TESTS_NO_YARA" in os.environ:
        return [(boreal, False)]
    else:
        import yara

        return [
            (boreal, False),
            (yara, True)
        ]


def modules():
    return [v[0] for v in modules_distinct()]


NB_COMPAT_ENTER_LOCK = Lock()
NB_COMPAT_ENTER = 0


class YaraCompatibilityMode:
    def __enter__(self):
        global NB_COMPAT_ENTER_LOCK
        with NB_COMPAT_ENTER_LOCK:
            global NB_COMPAT_ENTER
            NB_COMPAT_ENTER += 1

        boreal.set_config(yara_compatibility=True)

    def __exit__(self, *args):
        # Count the numbers of enter and exit: we
        # do not want to disable the config if some code is still
        # executing with this object alive.
        global NB_COMPAT_ENTER_LOCK
        with NB_COMPAT_ENTER_LOCK:
            global NB_COMPAT_ENTER
            NB_COMPAT_ENTER -= 1
            if NB_COMPAT_ENTER == 0:
                boreal.set_config(yara_compatibility=False)
