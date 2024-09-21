// [error: jump cannot have a length of 0]
rule a {
    strings:
        $a = { AB [0] 0F }
    condition:
        $a
}
