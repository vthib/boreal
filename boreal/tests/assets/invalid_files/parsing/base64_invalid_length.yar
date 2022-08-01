rule a {
    strings:
        $a = "a" base64("abc")
    condition:
        $a
}
