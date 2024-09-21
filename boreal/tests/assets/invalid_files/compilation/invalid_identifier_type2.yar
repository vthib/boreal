// [error: invalid identifier type]
import "pe"

rule c {
    condition:
        pe.os_version[2] == /aab/
}
