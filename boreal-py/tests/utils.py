import boreal
import yara

MODULES = [boreal, yara]
MODULES_DISTINCT = [
    (boreal, False),
    (yara, True),
]


class YaraCompatibilityMode:
    def __enter__(self):
        boreal.set_config(yara_compatibility=True)

    def __exit__(self, *args):
        boreal.set_config(yara_compatibility=False)
