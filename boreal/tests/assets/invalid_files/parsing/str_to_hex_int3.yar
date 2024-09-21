// [error: error converting hexadecimal notation to integer: invalid digit found in string]
rule a {
    strings:
        $a = /\x1/
    condition:
        $a
}
