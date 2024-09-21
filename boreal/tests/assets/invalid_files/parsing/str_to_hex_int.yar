// [error: error converting hexadecimal notation to integer: number too large to fit in target type]
rule a {
    condition:
        0x0123456789ABCDEFabcd
}
