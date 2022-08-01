import "pe"

rule c {
    condition:
        pe.os_version() == /aab/
}
