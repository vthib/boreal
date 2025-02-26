// [no libyara conformance]
// [max_strings_per_rule: 4]
// [error: the rule contains more than 4 strings]
rule a {
    strings:
        $a = "aaa"
        $b = "bbb"
        $c = "ccc"
        $d = "ddd"
        $e = "eee"
    condition:
        any of them
}
