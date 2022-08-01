rule a {
    strings:
        $a = "a" base64 xor base64
}
