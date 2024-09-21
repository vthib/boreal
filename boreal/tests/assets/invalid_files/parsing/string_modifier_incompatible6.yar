// [error: string modifiers base64 and fullword are incompatible]
rule a {
    strings:
        $a = "a" base64 private fullword
    condition:
        $a
}
