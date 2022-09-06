rule a {
    strings:
        $a = /a{5,4}/
    condition:
        $a
}
