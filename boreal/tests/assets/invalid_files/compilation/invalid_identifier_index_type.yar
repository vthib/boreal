import "pe"

rule a {
    condition:
        pe.sections["a"] == 3
}
