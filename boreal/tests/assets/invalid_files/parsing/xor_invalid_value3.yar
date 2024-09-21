// [error: syntax error]
rule a {
    strings:
        $a = "a" xor(-50-5)
    condition:
        $a
}
