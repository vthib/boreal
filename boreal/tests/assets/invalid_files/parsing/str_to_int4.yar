rule a {
    strings:
        $a = /a{0,10000000000}/
    condition:
        $a
}
