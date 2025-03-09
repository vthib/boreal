import boreal
import yara


MODULES = [boreal, yara]
MODULES_DISTINCT = [
    (boreal, False),
    (yara, True),
]
