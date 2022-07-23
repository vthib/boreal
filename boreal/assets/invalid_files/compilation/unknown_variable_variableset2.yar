rule a {
    strings:
        $a0 = "a0"
        $a1 = "a1"
    condition:
        all of ($a*, $b)
}
