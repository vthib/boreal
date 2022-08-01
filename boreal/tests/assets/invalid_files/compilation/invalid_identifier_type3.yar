import "pe"

rule c {
    condition:
        pe.sections.foo == /aab/
}
