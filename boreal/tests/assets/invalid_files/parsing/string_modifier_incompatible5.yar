// [error: string modifiers base64wide and nocase are incompatible]
rule a {
    strings:
        $a = "a" nocase base64wide
    condition:
        $a
}
