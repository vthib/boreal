// [error: string modifier base64 appears multiple times]
rule a {
    strings:
        $a = "a" base64 xor base64
}
