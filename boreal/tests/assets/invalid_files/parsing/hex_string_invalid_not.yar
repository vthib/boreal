// [error: syntax error]
rule a {
    strings:
        $a = { AB ~ ?? 0F }
    condition:
        $a
}
