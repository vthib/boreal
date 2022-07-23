rule a {
    strings:
        $a = "a" base64 nocase
    condition:
        $a
}
