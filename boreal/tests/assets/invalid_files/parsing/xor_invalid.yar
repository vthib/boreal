// [error: xor range invalid: 50 > 25]
rule a {
    strings:
        $a = "a" xor(50-25)
    condition:
        $a
}
