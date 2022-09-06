rule a {
    strings:
        $a = /[é]/
    condition:
        $a
}
