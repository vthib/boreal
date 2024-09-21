// [error: invalid range for the jump: 5 > 2]
rule a {
    strings:
        $a = { AB [5-2] 85 }
    condition:
        $a
}
