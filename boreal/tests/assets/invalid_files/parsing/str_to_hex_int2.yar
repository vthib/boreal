// [error: error converting hexadecimal notation to integer: invalid digit found in string]
rule a {
    strings:
        $a = /\xGR/
    condition:
        $a
}
