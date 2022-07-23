rule a {
    strings:
        $a = "a" xor(300-301)
    condition:
        $a
}
