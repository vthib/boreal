// [error: string modifiers base64wide and xor are incompatible]
rule a {
    strings:
        $a = "a" private xor base64wide
    condition:
        $a
}
