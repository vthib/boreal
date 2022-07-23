rule a {
    strings:
        $a = "a" wide xor xor(0-100)
}
