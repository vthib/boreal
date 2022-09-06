rule a {
    strings:
        $a = /\xGR/
    condition:
        $a
}
