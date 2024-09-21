// [error: xor range value 300 invalid, must be in [0-255]]
rule a {
    strings:
        $a = "a" xor(300-301)
    condition:
        $a
}
