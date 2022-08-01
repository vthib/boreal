rule a {
    strings:
        $a = "a" private xor base64wide
    condition:
        $a
}
