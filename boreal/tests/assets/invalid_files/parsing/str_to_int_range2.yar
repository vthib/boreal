rule a {
    strings:
        $a = { AB [0-100000000000000000000000] CD }
    condition:
        $a
}
