// [error: a list of tokens cannot start or end with a jump]
rule a {
    strings:
        $a = { [1-2] AB }
    condition:
        $a
}
