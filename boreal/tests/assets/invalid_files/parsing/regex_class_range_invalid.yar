// [error: invalid regex class range, start must be <= to end]
rule a {
    strings:
        $a = /[z-a]/
    condition:
        $a
}
