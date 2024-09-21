// [error: invalid regex range, start must be <= to end]
rule a {
    strings:
        $a = /a{5,4}/
    condition:
        $a
}
