// [error: string modifiers base64 and nocase are incompatible]
rule a {
    strings:
        $a = "a" base64 nocase
    condition:
        $a
}
