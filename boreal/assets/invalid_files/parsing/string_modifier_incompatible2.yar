rule a {
    strings:
        $a = "a" base64 xor
    condition:
        $a
}
