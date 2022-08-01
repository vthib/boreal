rule a {
    strings:
        $a = "a" xor(0-500)
    condition:
        $a
}
