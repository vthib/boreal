// [error: string modifiers xor and nocase are incompatible]
rule a {
    strings:
        $a = "a" xor private nocase
    condition:
        $a
}
