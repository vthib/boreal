// [error: negating an unknown byte is not allowed]
rule a {
    strings:
        $a = { AB ~?? 0F }
    condition:
        $a
}
