// [error: error converting to integer: number too large to fit in target type]
rule a {
    strings:
        $a = /a{0,10000000000}/
    condition:
        $a
}
