import "pe"

rule c {
    condition:
        pe.sections == /aab/
}
