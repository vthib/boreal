// [error: string modifiers base64wide and fullword are incompatible]
rule a {
    strings:
        $a = "a" fullword wide base64wide private
    condition:
        $a
}
