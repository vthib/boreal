rule a {
    strings:
        $a = { AB [5-2] 85 }
    condition:
        $a
}
