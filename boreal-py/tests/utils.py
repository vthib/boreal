import os

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


class YaraCompatibilityMode:
    def __enter__(self):
        boreal.set_config(yara_compatibility=True)

    def __exit__(self, *args):
        boreal.set_config(yara_compatibility=False)
