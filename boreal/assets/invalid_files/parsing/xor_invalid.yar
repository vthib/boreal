rule a {
    strings:
        $a = "a" xor(50-25)
    condition:
        $a
}
