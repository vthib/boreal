// [error: variable $a is unused]
rule a {
    strings:
        $a = "a"
    condition:
        true
}
