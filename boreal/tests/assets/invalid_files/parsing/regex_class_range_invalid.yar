rule a {
    strings:
        $a = /[z-a]/
    condition:
        $a
}
