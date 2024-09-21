// [error: error converting octal notation to integer: number too large to fit in target type]
rule a {
    condition:
        0o012345670123456701234567
}
