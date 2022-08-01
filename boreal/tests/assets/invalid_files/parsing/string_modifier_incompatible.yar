rule a {
    strings:
        $a = "a" xor private nocase
    condition:
        $a
}
