// [error: string modifiers base64 and xor are incompatible]
rule a {
    strings:
        $a = "a" base64 xor
    condition:
        $a
}
