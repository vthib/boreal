// [error: jumps over 200 not allowed inside alternations (|)]
rule a {
    strings:
        $a = { ( CD | AB [0-201] 85 ) }
    condition:
        $a
}
