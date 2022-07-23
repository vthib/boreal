rule a {
    strings:
        $a = "a" base64 private fullword
    condition:
        $a
}
