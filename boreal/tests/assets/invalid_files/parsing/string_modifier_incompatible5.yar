rule a {
    strings:
        $a = "a" nocase base64wide
    condition:
        $a
}
