rule a {
    strings:
        $a = /\x1/
    condition:
        $a
}
