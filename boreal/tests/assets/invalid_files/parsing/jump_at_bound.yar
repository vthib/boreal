rule a {
    strings:
        $a = { [1-2] AB }
    condition:
        $a
}
