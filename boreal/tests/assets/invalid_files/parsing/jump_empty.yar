rule a {
    strings:
        $a = { AB [0] 0F }
    condition:
        $a
}
