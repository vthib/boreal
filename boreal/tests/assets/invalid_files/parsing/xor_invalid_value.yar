// [error: xor range value 500 invalid, must be in [0-255]]
rule a {
    strings:
        $a = "a" xor(0-500)
    condition:
        $a
}
