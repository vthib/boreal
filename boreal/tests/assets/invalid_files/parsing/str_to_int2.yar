rule a {
    strings:
        $a = /a{10000000000}/
    condition:
        $a
}
